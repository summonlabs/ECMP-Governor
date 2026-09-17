#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <random>
#include <string>
#include <vector>

#include "ecmp/ecmp.hpp"
#include "test_framework.hpp"

namespace {

using namespace ecmp;

class AlwaysAuthorized final : public IPathAuthorityView {
 public:
  [[nodiscard]] std::optional<PathAuthorityObservation> observe(
      const PathId&) const override {
    PathAuthorityObservation observation;
    observation.generation = PathAuthorityGeneration::from_value(1);
    observation.authorized = true;
    return observation;
  }
};

struct Rig {
  AlwaysAuthorized view;
  GovernorLimits limits;
  SyntheticIds ids = synthetic_ids(1);
  PublisherId publisher = synthetic_publisher_id(1);
  WorkerBootId boot = synthetic_boot_id(1);
  std::unique_ptr<EcmpGovernor> governor;
  std::uint64_t attempts = 0;

  Rig() : governor(std::make_unique<EcmpGovernor>(GovernorLimits{}, CoordinatorEpoch::from_value(1),
                                                  &view)) {
    PublisherRegistration registration;
    registration.publisher = publisher;
    registration.worker_boot = boot;
    registration.scope = AuthorityScope::for_fabric(ids.fabric);
    registration.capabilities = 3;
    registration.provenance = ids.provenance;
    ConditionList conditions(64);
    (void)governor->register_publisher(governor->epoch(), registration, conditions);
  }

  AuthorityContext authority() {
    AuthorityContext context;
    context.epoch = governor->epoch();
    context.publisher = publisher;
    context.worker_boot = boot;
    context.scope = AuthorityScope::for_fabric(ids.fabric);
    ++attempts;
    context.attempt = synthetic_attempt_id(700000 + attempts);
    return context;
  }

  MutationResult create(std::uint64_t seed, std::uint32_t members, std::uint32_t buckets) {
    CreateGroupRequest request;
    request.authority = authority();
    request.group = synthetic_group_id(seed);
    request.key = synthetic_group_key(synthetic_ids(seed));
    request.cost_semantics = synthetic_cost_semantics(synthetic_ids(seed), 1);
    request.hash_domain = synthetic_ids(seed).hash_domain;
    request.provenance = synthetic_ids(seed).provenance;
    request.bucket_count = *BucketCount::make(buckets);
    request.min_active_members = 1;
    request.members = synthetic_members(synthetic_ids(seed), members,
                                        PathAuthorityGeneration::from_value(1));
    return governor->create_group(request);
  }
};

}  // namespace

ECMP_TEST(test_malformed_and_zero_identities_are_rejected) {
  Rig rig;
  ECMP_REQUIRE(is_acceptance(rig.create(1, 3, 16).outcome));

  // A nil member identity is malformed; a well formed member can be added once and
  // is then a duplicate.
  AddMemberRequest nil_member;
  nil_member.authority = rig.authority();
  nil_member.group = synthetic_group_id(1);
  nil_member.member = synthetic_member_spec(rig.ids, 3000, 3000, PathAuthorityGeneration::from_value(1));
  nil_member.member.member = ECMPMemberId{};
  ECMP_CHECK(rig.governor->add_member(nil_member).outcome == Outcome::MALFORMED_REQUEST);

  AddMemberRequest valid;
  valid.authority = rig.authority();
  valid.group = synthetic_group_id(1);
  valid.member = synthetic_member_spec(rig.ids, 3000, 3000, PathAuthorityGeneration::from_value(1));
  ECMP_CHECK(is_acceptance(rig.governor->add_member(valid).outcome));
  AddMemberRequest duplicate = valid;
  duplicate.authority = rig.authority();
  ECMP_CHECK(rig.governor->add_member(duplicate).outcome == Outcome::DUPLICATE_MEMBER);

  RemoveMemberRequest remove;
  remove.authority = rig.authority();
  remove.group = synthetic_group_id(1);
  remove.member = ECMPMemberId{};
  ECMP_CHECK(rig.governor->remove_member(remove).outcome == Outcome::UNKNOWN_MEMBER);

  RemoveMemberRequest unknown_group;
  unknown_group.authority = rig.authority();
  unknown_group.group = synthetic_group_id(9999);
  unknown_group.member = synthetic_member_id(2000);
  ECMP_CHECK(rig.governor->remove_member(unknown_group).outcome == Outcome::UNKNOWN_GROUP);

  // A nil path in a declaration is malformed rather than silently accepted.
  AddMemberRequest nil_path;
  nil_path.authority = rig.authority();
  nil_path.group = synthetic_group_id(1);
  nil_path.member = synthetic_member_spec(rig.ids, 3001, 3001, PathAuthorityGeneration::from_value(1));
  nil_path.member.path = PathId{};
  ECMP_CHECK(rig.governor->add_member(nil_path).outcome == Outcome::MALFORMED_REQUEST);

  // A nil cost provenance is malformed.
  AddMemberRequest nil_source;
  nil_source.authority = rig.authority();
  nil_source.group = synthetic_group_id(1);
  nil_source.member = synthetic_member_spec(rig.ids, 3002, 3002, PathAuthorityGeneration::from_value(1));
  nil_source.member.cost.source = ProvenanceId{};
  ECMP_CHECK(rig.governor->add_member(nil_source).outcome == Outcome::MALFORMED_REQUEST);
}

ECMP_TEST(test_scope_escalation_attempts_are_refused) {
  Rig rig;
  ECMP_REQUIRE(is_acceptance(rig.create(1, 2, 8).outcome));
  // A caller with a group-scoped grant cannot reach a different group.
  CreateGroupRequest other;
  other.authority = rig.authority();
  other.authority.scope = AuthorityScope::for_group(synthetic_group_id(1));
  other.group = synthetic_group_id(42);
  other.key = synthetic_group_key(synthetic_ids(42));
  other.cost_semantics = synthetic_cost_semantics(synthetic_ids(42), 1);
  other.hash_domain = synthetic_ids(42).hash_domain;
  other.provenance = synthetic_ids(42).provenance;
  other.bucket_count = *BucketCount::make(8);
  other.min_active_members = 1;
  other.members = synthetic_members(synthetic_ids(42), 2, PathAuthorityGeneration::from_value(1));
  ECMP_CHECK(rig.governor->create_group(other).outcome == Outcome::UNAUTHORIZED);
}

ECMP_TEST(test_resource_exhaustion_attempts_are_bounded) {
  GovernorLimits limits;
  limits.max_groups = 4;
  limits.max_members_per_group = 8;
  limits.max_buckets = 64;
  limits.max_batch_size = 8;
  Rig rig;
  rig.limits = limits;

  // A frame declaring an absurd payload is rejected before any allocation happens.
  Envelope envelope;
  envelope.message = WireMessageId::CREATE_GROUP;
  std::vector<std::uint8_t> oversized(limits.max_frame_bytes + 1, 0);
  envelope.payload = oversized;
  ECMP_CHECK(encode_frame(envelope, limits).empty());

  // A declared bucket count beyond the absolute ceiling cannot even be constructed.
  ECMP_CHECK(!BucketCount::make(0).has_value());
  ECMP_CHECK(!BucketCount::make(kAbsoluteMaxBuckets + 1).has_value());
  ECMP_CHECK(!BucketCount::make(0xFFFFFFFFu).has_value());

  // A payload declaring more members than the configured bound is rejected by the
  // decoder rather than partially consumed.
  CreateGroupRequest request;
  request.authority = rig.authority();
  request.group = synthetic_group_id(1);
  request.key = synthetic_group_key(rig.ids);
  request.cost_semantics = synthetic_cost_semantics(rig.ids, 1);
  request.hash_domain = rig.ids.hash_domain;
  request.provenance = rig.ids.provenance;
  request.bucket_count = *BucketCount::make(64);
  request.min_active_members = 1;
  request.members = synthetic_members(rig.ids, 64, PathAuthorityGeneration::from_value(1));
  const std::vector<std::uint8_t> bytes = encode_payload(request);
  CreateGroupRequest decoded;
  ECMP_CHECK(!decode_payload(bytes, limits, decoded));
}

ECMP_TEST(test_store_path_failures_are_reported_not_thrown) {
  Rig rig;
  ECMP_REQUIRE(is_acceptance(rig.create(1, 2, 8).outcome));

  // A store path whose parent is an existing file cannot be created.
  const std::filesystem::path directory =
      std::filesystem::temp_directory_path() / "ecmp-governor-adversarial";
  std::error_code error;
  std::filesystem::create_directories(directory, error);
  const std::filesystem::path file = directory / "blocking-file";
  {
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    out << "not a directory";
  }
  const SaveReport report = rig.governor->save(file / "store.bin");
  ECMP_CHECK(!report.ok);
  ECMP_CHECK(report.outcome == Outcome::STORE_ERROR);

  // Loading a nonexistent store reports a structured failure.
  const LoadReport load = rig.governor->load(directory / "missing.store");
  ECMP_CHECK(!load.ok);
  ECMP_CHECK(load.outcome == Outcome::STORE_ERROR);

  // Loading a directory as a store must not crash.
  const LoadReport directory_load = rig.governor->load(directory);
  ECMP_CHECK(!directory_load.ok);
  std::filesystem::remove(file, error);
}

ECMP_TEST(test_attempt_identifier_conflicts_and_replays) {
  Rig rig;
  ECMP_REQUIRE(is_acceptance(rig.create(1, 3, 16).outcome));

  AddMemberRequest first;
  first.authority = rig.authority();
  first.group = synthetic_group_id(1);
  first.member = synthetic_member_spec(rig.ids, 4000, 4000, PathAuthorityGeneration::from_value(1));
  const MutationAttemptId shared = first.authority.attempt;
  ECMP_REQUIRE(is_acceptance(rig.governor->add_member(first).outcome));

  AddMemberRequest replay = first;
  replay.authority = rig.authority();
  replay.authority.attempt = shared;
  ECMP_CHECK(rig.governor->add_member(replay).outcome == Outcome::IDEMPOTENT);

  AddMemberRequest conflict = first;
  conflict.authority = rig.authority();
  conflict.authority.attempt = shared;
  conflict.member = synthetic_member_spec(rig.ids, 4001, 4001, PathAuthorityGeneration::from_value(1));
  ECMP_CHECK(rig.governor->add_member(conflict).outcome == Outcome::ATTEMPT_CONFLICT);

  // Reusing an attempt identifier across different operation kinds is a conflict.
  RemoveMemberRequest cross_kind;
  cross_kind.authority = rig.authority();
  cross_kind.authority.attempt = shared;
  cross_kind.group = synthetic_group_id(1);
  cross_kind.member = synthetic_member_id(2000);
  ECMP_CHECK(rig.governor->remove_member(cross_kind).outcome == Outcome::ATTEMPT_CONFLICT);
}

ECMP_TEST(test_epoch_advance_invalidates_live_authority_but_keeps_definitions) {
  Rig rig;
  ECMP_REQUIRE(is_acceptance(rig.create(1, 3, 16).outcome));
  const std::optional<GroupSnapshot> before = rig.governor->snapshot(synthetic_group_id(1));
  ECMP_REQUIRE(before.has_value());

  ConditionList conditions(64);
  ECMP_REQUIRE(rig.governor->set_epoch(CoordinatorEpoch::from_value(2), conditions));
  ECMP_CHECK(!rig.governor->set_epoch(CoordinatorEpoch::from_value(2), conditions));
  ECMP_CHECK(!rig.governor->set_epoch(CoordinatorEpoch::from_value(1), conditions));

  const std::optional<GroupSnapshot> after = rig.governor->snapshot(synthetic_group_id(1));
  ECMP_REQUIRE(after.has_value());
  ECMP_CHECK(after->currentness.has(CurrentnessCause::STALE_EPOCH));
  ECMP_CHECK(after->lifecycle == GroupLifecycle::REVALIDATION_REQUIRED);
  // The durable definition and the desired assignment survive the epoch advance.
  ECMP_CHECK(after->assignment.owners == before->assignment.owners);
  ECMP_CHECK_EQ(after->declared_member_count(), before->declared_member_count());
  ECMP_CHECK(after->authority_generation.value() > before->authority_generation.value());

  // Old epoch traffic is rejected; the publisher registry is emptied.
  AddMemberRequest stale;
  stale.authority.epoch = CoordinatorEpoch::from_value(1);
  stale.authority.publisher = rig.publisher;
  stale.authority.worker_boot = rig.boot;
  stale.authority.scope = AuthorityScope::for_fabric(rig.ids.fabric);
  stale.authority.attempt = synthetic_attempt_id(1);
  stale.group = synthetic_group_id(1);
  stale.member = synthetic_member_spec(rig.ids, 5000, 5000, PathAuthorityGeneration::from_value(1));
  ECMP_CHECK(rig.governor->add_member(stale).outcome == Outcome::STALE_EPOCH);

  AddMemberRequest unregistered = stale;
  unregistered.authority.epoch = rig.governor->epoch();
  ECMP_CHECK(rig.governor->add_member(unregistered).outcome == Outcome::UNAUTHORIZED);
}

ECMP_TEST(test_fence_table_is_bounded_and_epoch_advance_clears_it) {
  GovernorLimits limits;
  limits.max_publishers = 2;
  std::string reason;
  ECMP_REQUIRE(limits.is_coherent(reason));

  AlwaysAuthorized view;
  EcmpGovernor governor(limits, CoordinatorEpoch::from_value(1), &view);
  ConditionList conditions(limits.max_explanation_entries);
  for (std::uint32_t index = 0; index < 4; ++index) {
    PublisherRegistration registration;
    registration.publisher = synthetic_publisher_id(1);
    registration.worker_boot = synthetic_boot_id(index + 1);
    registration.scope = AuthorityScope::for_fabric(synthetic_ids(1).fabric);
    registration.capabilities = 3;
    registration.provenance = synthetic_ids(1).provenance;
    const Outcome outcome =
        governor.register_publisher(governor.epoch(), registration, conditions);
    // The publisher limit bounds live registrations; repeated re-registration with
    // fresh boots accumulates fence records until the configured bound is reached.
    ECMP_CHECK(outcome == Outcome::REGISTERED || outcome == Outcome::RESOURCE_LIMIT);
  }
  // An epoch advance clears the fence table, so registration works again.
  ECMP_REQUIRE(governor.set_epoch(CoordinatorEpoch::from_value(2), conditions));
  PublisherRegistration registration;
  registration.publisher = synthetic_publisher_id(1);
  registration.worker_boot = synthetic_boot_id(9);
  registration.scope = AuthorityScope::for_fabric(synthetic_ids(1).fabric);
  registration.capabilities = 3;
  registration.provenance = synthetic_ids(1).provenance;
  ECMP_CHECK(governor.register_publisher(governor.epoch(), registration, conditions) ==
             Outcome::REGISTERED);
}

ECMP_TEST(test_notifications_require_upstream_authority) {
  Rig rig;
  ECMP_REQUIRE(is_acceptance(rig.create(1, 3, 16).outcome));

  // A publisher that only holds MUTATE_GROUP cannot inject an upstream fact.
  const PublisherId mutate_only = synthetic_publisher_id(77);
  const WorkerBootId mutate_only_boot = synthetic_boot_id(77);
  {
    PublisherRegistration registration;
    registration.publisher = mutate_only;
    registration.worker_boot = mutate_only_boot;
    registration.scope = AuthorityScope::for_fabric(rig.ids.fabric);
    registration.capabilities = 1;  // MUTATE_GROUP only
    registration.provenance = rig.ids.provenance;
    ConditionList conditions(64);
    ECMP_REQUIRE(rig.governor->register_publisher(rig.governor->epoch(), registration, conditions) ==
                 Outcome::REGISTERED);
  }
  PathAuthorityChangeNotice notice;
  notice.epoch = rig.governor->epoch();
  notice.publisher = mutate_only;
  notice.worker_boot = mutate_only_boot;
  notice.path = synthetic_path_id(1000);
  notice.generation = PathAuthorityGeneration::from_value(2);
  ECMP_CHECK(rig.governor->notify_path_authority_change(notice).outcome == Outcome::UNAUTHORIZED);
  notice.publisher = rig.publisher;
  notice.worker_boot = rig.boot;

  // A stale epoch is refused before anything else.
  notice.epoch = CoordinatorEpoch::from_value(9);
  ECMP_CHECK(rig.governor->notify_path_authority_change(notice).outcome == Outcome::STALE_EPOCH);

  // A notification for a path no group depends on is accepted as a no-op.
  notice.epoch = rig.governor->epoch();
  notice.path = synthetic_path_id(999999);
  ECMP_CHECK(rig.governor->notify_path_authority_change(notice).outcome == Outcome::NO_CHANGE);

  // A nil path is malformed.
  notice.path = PathId{};
  ECMP_CHECK(rig.governor->notify_path_authority_change(notice).outcome ==
             Outcome::MALFORMED_REQUEST);
}
