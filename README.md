# ECMP Governor

**ECMP Governor 1.0.0** is the deterministic equal-cost multipath membership,
eligibility and rebalance-governance runtime of the Distributed Fabric
Infrastructure / Fabric OS stack, published by Summon Software Labs.

It answers exactly one question:

> Which exact currently legal equal-cost paths belong to this ECMP group right
> now, which members are eligible for forwarding, which bucket assignment is
> authoritative, under which generations and provenance, and how may membership or
> assignment change without stale authority, uncontrolled churn, or silent
> inconsistency?

ECMP Governor governs the **desired control-plane ECMP assignment**. It does not
program hardware, does not move packets and does not measure traffic.

## Boundary

ECMP Governor owns:

- ECMP group identity, lifecycle, membership generation, assignment generation
  and authority generation;
- equal-cost membership and equality-class validation;
- member eligibility and currentness;
- deterministic member ordering, deterministic bucket assignment and
  deterministic minimal-churn rebalance;
- stable rebalance planning, stale-assignment rejection and assignment
  supersession;
- administrative disablement, fencing, revalidation, revocation, retirement,
  supersession;
- deterministic snapshots, diffs, semantic digests, structured explanations,
  persistence and conservative recovery;
- distributed mutation authority, real worker-death and coordinator-restart proof.

ECMP Governor does **not** own, and never reimplements:

| Domain | Owner | What ECMP Governor does instead |
| --- | --- | --- |
| canonical entity identity | Fabric Registry | consumes PathId, FabricId, RoutingNamespaceId, DestinationId |
| topology | Fabric Topology | never walks the graph, never runs Dijkstra or Yen |
| live link health | Link State Fabric | never reads link state |
| port configuration | Port Fabric | never touches ports |
| capability truth | Fabric Capability Registry | never infers capability |
| failure-domain truth | Failure Domain Registry | never derives failure domains |
| epoch issuance | Fabric Epoch | consumes the current CoordinatorEpoch |
| path computation | Path Planner | never searches for or ranks candidate paths |
| path legality | Path Authority | consumes IPathAuthorityView observations; a stale binding makes a member ineligible |
| route lifecycle | Route Fabric | never creates, installs, withdraws or supersedes a route |
| simultaneous multipath membership | Multipath Fabric | consumes IMultipathSetView; the exact set generation must still contain the member |
| non-equal path weighting | Weighted Path Fabric | refuses unequal costs; no member weights exist |
| congestion-driven adaptation | Adaptive Routing | reacts only to authoritative eligibility changes, never to telemetry |
| global convergence ordering | Route Convergence | publishes the new authoritative ECMP state, never sequences FIB updates |

**Equal cost and ECMP membership are separate facts.** A path may be equal-cost,
currently legal and part of a multipath set and still not be an active ECMP
member. An active ECMP member does not imply equal observed traffic, equal
congestion, equal utilisation, equal packet counts or equal latency. ECMP Governor
governs deterministic assignment semantics, not traffic outcome.

## Equal-cost semantics

Cost is a deterministic bounded integer pair, never floating point:

    struct PathCost { std::int64_t units; std::uint32_t scale; };  // scale <= 9

to_text() renders a canonical decimal form (12345, 12.345, -0.05). Equality is
**exact field equality**: identical units and identical scale. 12.345 and 12345
with different scales are never silently equal.

Every cost claim carries its provenance:

    struct CostModelBinding {
      CostModelId model; std::uint32_t model_version;
      RouteClassId route_class; CostPolicyGeneration policy_generation;
    };
    struct CostClaim { CostClassId cost_class; CostModelBinding binding;
                       PathCost cost; ProvenanceId source; };

compare_cost_claim returns exactly one of EQUAL, CLASS_MISMATCH, MODEL_MISMATCH,
POLICY_STALE or VALUE_MISMATCH, and the governor maps those to
COST_CLASS_MISMATCH, STALE_COST_GENERATION and COST_MISMATCH. Equal numeric values
under two different cost models never imply equal-cost membership.

A cost-policy generation change invalidates every equal-cost proof: the group
enters REVALIDATION_REQUIRED with the STALE_COST_CLASS currentness cause. A group
may only adopt a new policy generation when **every declared member** is re-proved
under one single compatible binding and that generation is the one the cost
authority currently reports. Partial reproof is refused.

## Identities, keys and generations

Identities are 128-bit strongly typed values (ECMPGroupId, ECMPMemberId, PathId,
MultipathSetId, RouteId, PublisherId, WorkerBootId, MutationAttemptId,
RebalancePlanId, HashDomainId, CostClassId, CostModelId, RouteClassId, FabricId,
RoutingNamespaceId, DestinationId, ProvenanceId). Each has its own tag type:
passing an ECMPMemberId where an ECMPGroupId is expected does not compile. The
canonical text encoding is exactly 32 lowercase hexadecimal digits; parsing
accepts either case and rejects every other spelling. Nil identities are rejected
wherever an identity is required.

The semantic group key is

    struct GroupKey { FabricId fabric; RoutingNamespaceId routing_namespace;
                      DestinationId destination; CostClassId cost_class; };

Generation, process incarnation and mutable display labels are deliberately
absent: identity stays stable across ordinary member mutation, and change is
expressed only through generations.

- MembershipGeneration advances when the **declared member set** changes.
- AssignmentGeneration advances when **bucket ownership** changes.
- AuthorityGeneration advances when the **authority binding** changes (new
  coordinator epoch, new publisher incarnation, epoch advance, recovery).

All three are checked 64-bit counters. Crossing 2^64 - 1 yields no successor: the
operation is refused with GENERATION_EXHAUSTED rather than wrapping.

A member is never identified by vector position; its ECMPMemberId is its identity
and the canonical order is derived, not stored.

## Membership modes

DIRECT_PATH_SET — the caller declares an explicit exact path set. ECMP Governor
validates path authority and cost equality itself and claims no upstream
multipath-set governance.

MULTIPATH_FABRIC — membership is bound to an exact MultipathSetId and
MultipathSetGeneration. The upstream set must still contain every member; a stale
set generation invalidates every member and the group requires revalidation. ECMP
Governor does not duplicate generic multipath lifecycle.

The two modes have separate validation rules and are never conflated.

## Eligibility and lifecycle

A member is ECMP-eligible only when **all** of the following hold: it exists and is
declared; its path authority binding matches the current observation and the path
is authorised; its equal-cost proof is current; the group lifecycle permits
membership; it is administratively enabled; the publisher and epoch authority are
current; and, in multipath mode, the exact multipath set generation still contains
it. A stale member is never counted active and never keeps a bucket.

Member states: ACTIVE, REVALIDATION_REQUIRED, INELIGIBLE, WITHDRAWN, RETIRED.
ELIGIBLE and ACTIVE are deliberately collapsed in 1.0.0 because the governor
enforces bucket_count >= maximum members per group, so an eligible member always
owns at least one bucket. PENDING is likewise unobservable because membership is
validated synchronously and atomically at declaration. There is no dead state.

Group states: DECLARED, ACTIVE, DEGRADED, REVALIDATION_REQUIRED, REBALANCING,
WITHDRAWING, WITHDRAWN, REVOKED, SUPERSEDED, RETIRED. The derived state is a pure
function of counts, plan presence and authority currentness:

    plan pending           -> REBALANCING
    no declared member     -> DECLARED
    no active member       -> REVALIDATION_REQUIRED
    authority not current  -> REVALIDATION_REQUIRED
    active < minimum       -> DEGRADED
    otherwise              -> ACTIVE

WITHDRAWING, WITHDRAWN, REVOKED, SUPERSEDED and RETIRED are sticky and are never
left. The full 10 x 18 transition matrix is exercised exhaustively by the test
suite against an independently written table.

Minimum-active-member semantics: with min_active = 2, three active members give
ACTIVE, two give ACTIVE, one gives DEGRADED, zero gives REVALIDATION_REQUIRED, and
no declared members give DECLARED.

Currentness causes are never collapsed into one "stale" flag:
STALE_PATH_AUTHORITY, STALE_MULTIPATH_SET, STALE_COST_CLASS, STALE_EPOCH,
FENCED_PUBLISHER, REVALIDATION_REQUIRED, RETIRED. A stale path on one member does
not void the group's live authority; it makes that member ineligible.

Revocation, withdrawal, supersession and retirement are distinct and durable: a
revoked group rejects every mutation, and nothing resurrects it.

## Bucket model and deterministic assignment

The selection space is the bounded abstract hash domain `[0, bucket_count)`.
bucket_count is validated against GovernorLimits::max_buckets (default 1024,
absolute ceiling 2^20) and against the member count: a group can never declare more
members than buckets, so no active member owns zero buckets.

Initial assignment for N members over B buckets gives the first B mod N canonical
members one extra bucket: 8/2 = 4,4; 8/3 = 3,3,2; 16/5 = 4,3,3,3,3. Buckets are
handed out in ascending bucket order to members in canonical order, so the
assignment is a pure function of the canonical member list. Every bucket has
exactly one owner and the total is always bucket_count.

The canonical member order is (PathId, ECMPMemberId) ascending. Creating the same
group from the same declaration with members presented in any order produces an
identical canonical member list, identical membership digest, identical assignment
digest and identical generations; this is asserted for every permutation in the
test suite.

## Rebalance and the churn guarantee

When the eligible set changes from A to B, ECMP Governor computes the
**minimum-churn** balanced assignment:

    churn = bucket_count - sum over members of min(previous_share, target_share)

Each member keeps as many of its own lowest-numbered buckets as its target share
allows; freed buckets are handed out in ascending bucket order to members in
canonical order until every deficit is satisfied. Among all minimum-churn
assignments the result is the lexicographically smallest owner vector.

The guarantee is checked against independent methods in the same test run:

1. the closed form above;
2. a maximum-flow computation over "which buckets can keep their owner";
3. exhaustive enumeration for tiny instances (up to 6 buckets and 3 members);
4. a depth-first search in owner order returning the lexicographically smallest
   minimum-churn assignment for bucket_count <= 16 and member_count <= 5.

Production rebalance is asserted equal to the search result for 400 randomised
instances and equal to the brute-force result for 120 more. There is no unnecessary
movement beyond the documented minimum: removing one of four equal members over 64
buckets moves exactly that member's 16 buckets and leaves every other owner
untouched.

Every move is represented explicitly as (BucketId, from, to, reason) with the
reason INITIAL_ASSIGNMENT, OWNER_REMOVED or OWNER_OVER_QUOTA, so "why did bucket 17
move from A to B" has an exact answer. Buckets are never hidden behind a whole-map
replacement.

RebalancePlanId is derived deterministically from the group identity, the
generations the plan was computed from and the target membership digest, so
planning the same change twice yields the same plan identity.

## Invalidation, currentness and watermarks

Path Authority change notices are re-observed through the governor's own
IPathAuthorityView. The notice is never treated as an observation: a claim that
does not change any observation is accepted as NO_CHANGE.

Reverse indexes make invalidation precise: PathId -> groups, MultipathSetId ->
groups, CostClassId -> groups, PublisherId -> groups. A notification for a path no
group depends on is NO_CHANGE and leaves every semantic digest untouched.

A rebalance plan is bound to the exact membership, assignment and authority
generations it was computed from. Committing a plan after an authoritative
invalidation, epoch advance, fence or membership change is refused as STALE_PLAN
and the state is provably unchanged. Membership mutation while a plan is pending is
refused as LIFECYCLE_VIOLATION rather than silently completing a stale rebalance.
Both races are exercised with real threads, and every interleaving is asserted to
end in a fully valid state.

## Fencing, epochs and restart semantics

Every mutation binds the coordinator epoch, the publisher identity, the worker boot
identity, an explicit authority scope, the expected generations and a
MutationAttemptId. Connected is not authorised; a known publisher is not
authorised; durable state is not live authority. Authority scope defaults to deny
all and is never wildcard. A group-scoped grant is checked before the group is even
looked up; broader grants are checked against the resolved key.

An exact replay of an accepted mutation with the same MutationAttemptId and the same
payload returns IDEMPOTENT and advances nothing, not even a generation. Reusing an
attempt identifier with a different payload is refused as ATTEMPT_CONFLICT. The
idempotency window is bounded by GovernorLimits::max_attempts_remembered and the
bound is documented behaviour.

A fenced worker boot can never mutate again for the lifetime of the epoch in which
it was fenced, and may not re-register. A fresh boot for the same publisher
identity is a fresh registration that must explicitly revalidate the groups it
wants to own. An epoch advance invalidates every live authority: the publisher
registry and the fence table are cleared, every group's upstream proofs become
unproven, and every group requires explicit revalidation — while the durable
definition and the durable desired bucket assignment survive.

## Persistence and recovery

The store is versioned, integrity-checked and deterministically encoded:

    magic[8] "ECMPGOV" 0x01 | format_version u32 | reserved u32 |
    coordinator_epoch u64 | payload_bytes u32 | payload | tag[32] SHA-256

Bucket maps are persisted as explicit (bucket, owner) pairs, so a duplicate bucket,
a missing bucket and an out-of-range bucket are all detectable — a dense vector
cannot express them. Decoding is strict: wrong magic, wrong version, non-zero
reserved field, truncation, trailing bytes, integrity failure, oversized payload,
duplicate group, duplicate member, unknown bucket owner, impossible generation,
invalid lifecycle, malformed cost class, impossible member count and implied
arithmetic overflow are each rejected with a distinct stable defect code.

Files are replaced atomically: the new image is written to a temporary file,
flushed, and moved over the target. A crash leaves either the old complete file or
the new complete file, never a mixture, and a leftover temporary file carries no
authority.

Recovery is conservative. A recovered group keeps its durable definition and its
durable desired bucket assignment but has **no** live authority: every member is
REVALIDATION_REQUIRED, the currentness causes are STALE_EPOCH and
REVALIDATION_REQUIRED, and the pending plan is dropped. The authority generation
advances because the coordinator incarnation changed. Explicit revalidation
re-observes path authority and the multipath binding and restores the identical
bucket map — the durable map is already balanced for the same member set, so the
restore has zero churn and an identical assignment digest. The epoch advances
monotonically and is persisted before the coordinator serves a single request, so a
second restart observes a strictly larger epoch.

## Distributed model and protocol

The wire protocol is framed with an explicit version, stable explicit numeric
message identifiers (never enum ordinals), a bounded frame length, deterministic
little-endian encoding, strict enum validation, strict trailing-byte rejection and
an integrity tag over the semantic header **and** payload. A peer that stops
mid-frame is disconnected with an explicit PEER_TIMEOUT failure after the
configured receive budget: a partial frame cannot pin a session forever, and that
is product behaviour rather than a test timeout.

**ECMP Governor 1.0.0 is not a consensus system.** Exactly one coordinator owns a
store at a time and stale epochs are fenced by epoch comparison, not by distributed
agreement. Isolated split-brain coordinators are not prevented by shared exclusion
or consensus; running two coordinators against one store is a configuration error.
There is **no cryptographic authentication** anywhere: the digest detects
corruption and accidental divergence, it is not a MAC and it does not authenticate
peers. Registration is a stated trust boundary on a loopback/trusted-network
deployment.

The coordinator stamps the authority scope it actually granted; a client cannot
widen its own scope. Mutations and their autosave are serialised so the durable
store always reflects a monotonically newer state.

## REAL / SYNTHETIC / UNSUPPORTED evidence

**REAL** (proven by the test suite on this host):

- actual OS process death: a real worker process is terminated with
  TerminateProcess, the coordinator detects the disconnect and fences the
  incarnation, the dead boot can never mutate again, a fresh boot re-registers and
  revalidates, and an unrelated publisher and its group are unaffected;
- actual coordinator restart: the coordinator process is hard-killed and restarted
  from the same durable store; definitions survive, live authority does not, the
  epoch advances monotonically across repeated restarts, and old-epoch traffic is
  rejected;
- actual loopback transport over TCP with bounded framed reads;
- actual persistence, including a truncation sweep at every byte position and a
  bit-flip sweep;
- real concurrency: conflicting mutations, invalidation racing a rebalance commit,
  and concurrent queries with independent group mutations.

**SYNTHETIC** (clearly labelled, never presented as physical proof):

- path identities, cost claims, group keys and member identities derived
  deterministically from seeds (ecmp/synthetic.hpp);
- the file-backed authority view used by the distributed proofs as a stand-in for a
  Path Authority / Multipath Fabric runtime;
- leaf-spine-like group shapes, high path multiplicity, bucket maps.

**UNSUPPORTED** in 1.0.0 (and never claimed):

- physical switch ASIC ECMP programming of any kind;
- physical multi-switch convergence;
- actual flow hashing and real traffic balancing;
- measured equal traffic distribution;
- vendor SDK integration.

The authoritative assignment governed here is **control-plane desired state**. There
is no APPLIED_ASSIGNMENT in 1.0.0 because no backend is implemented; desired and
applied state are never collapsed, and nothing in this repository reads or writes a
host routing table as evidence.

## Build

Requirements: Windows 10/11 x64, Visual Studio 2022 (MSVC 19.4x) or newer, CMake
3.25+ and Ninja. The control-plane library is portable C++20, but 1.0.0 is validated
on Windows only, and the build refuses to configure elsewhere rather than pretending
otherwise.

    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build

Options: ECMP_BUILD_TESTS, ECMP_BUILD_EXAMPLES, ECMP_BUILD_BENCHMARKS,
ECMP_BUILD_APPS, ECMP_WARNINGS_AS_ERRORS (default ON), ECMP_ENABLE_ANALYZE,
ECMP_ENABLE_ASAN.

First-party code is compiled with /W4 /permissive- /Zc:__cplusplus /utf-8 /EHsc /WX.
There are no warning suppressions for first-party code.

## Test

    ctest --test-dir build --output-on-failure

Ten CTest entries cover: core identities, codecs, digests and both rebalance
oracles; governor semantics; persistence corruption; protocol framing; randomised
property schedules and deterministic races; adversarial input; scale; real
distributed process proofs; and both examples. There are no test timeouts, no
retries and no watchdogs: a hanging test is a defect. The only bounded waits are
internal, and exhausting one produces an explicit failed assertion.

## Install and find_package

    cmake --install build --prefix <prefix>

    find_package(ECMPGovernor CONFIG REQUIRED)
    target_link_libraries(app PRIVATE SummonSoftwareLabs::ECMPGovernor)

The package exports the imported target SummonSoftwareLabs::ECMPGovernor together
with its include directories and its platform link dependencies. A downstream
consumer that only uses the installed artifacts is built and run as part of release
validation, and it must find the package, compile, link, create a synthetic group,
add three equal-cost path members, verify the deterministic bucket assignment,
remove a member, verify the deterministic rebalance, and exit successfully.

## Examples

    build/examples/ecmp_example_api          # two-way, three-way, bucket split,
                                             # removal, restoration, stale path
                                             # authority, cost mismatch
    build/examples/ecmp_example_distributed  # real processes: worker death,
                                             # fencing, coordinator restart,
                                             # fresh-boot revalidation

Both examples assert their expected outcomes and exit non-zero on any mismatch.

The ecmp_coordinator, ecmp_worker and ecmp_cli applications are installed alongside
the library. The CLI exposes version, store inspect, group create|show|list, member
add|remove|disable|enable|revalidate, rebalance, explain, snapshot and diff, with
deterministic key=value output.

## Benchmarks

    build/bench/ecmp_benchmark

Observed on the development host (Windows 11, MSVC 19.44, x64 Release, 16 logical
processors) as completed operations:

| Operation | Completed | Elapsed | Per second |
| --- | --- | --- | --- |
| group_create | 10000 | 350 ms | ~28 500 |
| member_add_with_rebalance (64 buckets) | 10000 | 303 ms | ~33 000 |
| member_remove_with_rebalance (64 buckets) | 10000 | 268 ms | ~37 300 |
| snapshot_with_digest | 10000 | 133 ms | ~75 400 |
| list_groups | 10000 | 130 ms | ~77 100 |
| persistence_save (33.7 MB store) | 10000 | 140 ms | ~71 200 |
| persistence_load_and_recover | 10000 | 241 ms | ~41 400 |
| invariant_check | 10000 | 25 ms | ~395 800 |
| group_create_100k (16 buckets) | 100000 | 2864 ms | ~34 900 |
| invariant_check_100k | 100000 | 1718 ms | ~58 200 |

These are machine and build observations for this host, not product claims.

## Genuine limitations

- **Physical semantics are unsupported.** No switch ASIC programming, no real
  traffic balancing, no convergence, no traffic engineering, no bandwidth
  reservation, no flow scheduling, no global load balancing, no path diversity
  analysis. The governed assignment is desired control-plane state.
- **No weighting and no adaptation.** Every active member owns a near-equal share;
  50/20/20/10 splits, capacity weighting, congestion weighting, telemetry-driven
  membership and latency-driven membership do not exist here.
- **No route authority.** ECMP Governor never installs, withdraws or supersedes a
  route, and never claims that a route was programmed.
- **No consensus and no cryptography.** A single authoritative coordinator owns a
  store; split brain is a configuration error. Digests detect corruption, not
  forgery, and peers are not authenticated.
- **Fencing scope.** A fenced boot can never mutate again within its epoch. Across
  an epoch advance every registration is a fresh grant, because the coordinator
  keeps no cross-epoch per-boot state; the governor does not claim cross-epoch
  replay protection for a boot identity.
- **Server serialisation.** The coordinator applies mutations (and their autosave)
  one at a time. Library callers may mutate concurrently from any thread; the
  coordinator chooses a single writer so the durable store stays monotonic.
- **Order independence is precise, not absolute.** Rebalance is a pure function of
  the previous authoritative bucket map, the canonical member list and the bucket
  count. Consequently equivalent declarations in any input order, and replays of
  the same sequence of semantic states, are identical; two groups that reach the
  same member set through different intermediate states have identical canonical
  membership, costs, lifecycle and generations but may differ in exactly the
  buckets whose movement minimal churn requires. That is unavoidable: an
  insertion-order-independent map would have to give up churn minimality, and churn
  minimality is the governing requirement.
- **Idempotency window.** Attempt replay memory is bounded; once an attempt falls
  out of the configured window it is judged on its own merits rather than reported
  as a replay.
- **Generation exhaustion.** Membership, assignment and authority generations are
  checked counters. Exhaustion is refused with GENERATION_EXHAUSTED (2^64 semantic
  changes would be required to observe it); the unit tests verify the non-wrapping
  arithmetic directly.
- **Platform.** 1.0.0 is validated on Windows x64 only. The portable core is C++20
  with no OS headers, but no non-Windows build is claimed or tested.
- **Representation versions are independent of the product version.** Wire version,
  persistence format version, digest encoding version and assignment algorithm
  version do not change merely because the product version changes.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
