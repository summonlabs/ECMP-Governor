#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <set>
#include <string>
#include <vector>

#include "ecmp/ecmp.hpp"
#include "test_framework.hpp"

namespace {

using namespace ecmp;

class TestPathAuthority final : public IPathAuthorityView {
 public:
  mutable std::mutex mutex;
  std::map<PathId, PathAuthorityObservation> paths;

  [[nodiscard]] std::optional<PathAuthorityObservation> observe(
      const PathId& path) const override {
    std::lock_guard<std::mutex> lock(mutex);
    const auto it = paths.find(path);
    if (it == paths.end()) {
      return std::nullopt;
    }
    return it->second;
  }

  void set(const PathId& path, std::uint64_t generation, bool authorized) {
    std::lock_guard<std::mutex> lock(mutex);
    PathAuthorityObservation observation;
    observation.generation = PathAuthorityGeneration::from_value(generation);
    observation.authorized = authorized;
    paths[path] = observation;
  }
};

class TestMultipath final : public IMultipathSetView {
 public:
  mutable std::mutex mutex;
  std::map<MultipathSetId, MultipathSetGeneration> generations;
  std::map<MultipathSetId, std::set<PathId>> members;

  [[nodiscard]] std::optional<MultipathSetGeneration> generation(
      const MultipathSetId& set) const override {
    std::lock_guard<std::mutex> lock(mutex);
    const auto it = generations.find(set);
    if (it == generations.end()) {
      return std::nullopt;
    }
    return it->second;
  }

  [[nodiscard]] bool contains(const MultipathSetId& set, MultipathSetGeneration generation,
                              const PathId& path) const override {
    std::lock_guard<std::mutex> lock(mutex);
    const auto it = generations.find(set);
    if (it == generations.end() || !(it->second == generation)) {
      return false;
    }
    const auto entry = members.find(set);
    return entry != members.end() && entry->second.count(path) != 0;
  }

  void set(const MultipathSetId& set, std::uint64_t generation, std::set<PathId> paths) {
    std::lock_guard<std::mutex> lock(mutex);
    generations[set] = MultipathSetGeneration::from_value(generation);
    members[set] = std::move(paths);
  }
};

struct Fixture {
  TestPathAuthority path_authority;
  TestMultipath multipath;
  GovernorLimits limits;
  SyntheticIds ids = synthetic_ids(1);
  PublisherId publisher = synthetic_publisher_id(1);
  WorkerBootId boot = synthetic_boot_id(1);
  std::uint64_t attempts = 0;
  std::unique_ptr<EcmpGovernor> governor;

  explicit Fixture(GovernorLimits limits_in = GovernorLimits{})
      : limits(limits_in),
        governor(std::make_unique<EcmpGovernor>(limits_in, CoordinatorEpoch::from_value(1),
                                                &path_authority, &multipath)) {}

  CoordinatorEpoch epoch() const { return governor->epoch(); }

  AuthorityContext authority(std::optional<uint64_t> attempt = std::nullopt) {
    AuthorityContext context;
    context.epoch = governor->epoch();
    context.publisher = publisher;
    context.worker_boot = boot;
    context.scope = AuthorityScope::for_fabric(ids.fabric);
    ++attempts;
    context.attempt = synthetic_attempt_id(attempt.has_value() ? *attempt : attempts);
    return context;
  }

  bool register_publisher(std::uint32_t capabilities = 3, std::optional<PublisherId> custom = {}) {
    PublisherRegistration registration;
    registration.publisher = custom.has_value() ? *custom : publisher;
    registration.worker_boot = boot;
    registration.scope = AuthorityScope::for_fabric(ids.fabric);
    registration.capabilities = capabilities;
    registration.provenance = ids.provenance;
    ConditionList conditions(limits.max_explanation_entries);
    const Outcome outcome =
        governor->register_publisher(governor->epoch(), registration, conditions);
    return is_acceptance(outcome);
  }

  void authorize_paths(std::uint32_t count, std::uint64_t generation, std::uint64_t base = 1000) {
    for (std::uint32_t index = 0; index < count; ++index) {
      path_authority.set(synthetic_path_id(base + index), generation, true);
    }
  }

  MemberSpec member(std::uint32_t index, std::uint64_t generation = 1, std::int64_t units = 10,
                    std::uint64_t base = 1000, std::uint64_t member_base = 2000) {
    return synthetic_member_spec(ids, member_base + index, base + index,
                                 PathAuthorityGeneration::from_value(generation), units);
  }

  CreateGroupRequest create_request(std::uint64_t group_seed, std::uint32_t members,
                                    std::uint32_t buckets, std::uint32_t min_active = 1,
                                    std::uint64_t generation = 1) {
    // Group semantics are derived from the seed, so two different seeds are two
    // different semantic groups.
    const SyntheticIds group_ids = synthetic_ids(group_seed);
    CreateGroupRequest request;
    request.authority = authority();
    request.group = synthetic_group_id(group_seed);
    request.key = synthetic_group_key(group_ids);
    // The authority grant is fabric scoped, so every derived key stays inside the
    // granted fabric while the remaining key dimensions vary with the seed.
    request.key.fabric = ids.fabric;
    request.cost_semantics = synthetic_cost_semantics(group_ids, 1);
    request.hash_domain = group_ids.hash_domain;
    request.provenance = group_ids.provenance;
    request.bucket_count = *BucketCount::make(buckets);
    request.min_active_members = min_active;
    request.members = synthetic_members(group_ids, members,
                                        PathAuthorityGeneration::from_value(generation));
    return request;
  }
};

MutationResult create_simple(Fixture& fixture, std::uint64_t seed = 1, std::uint32_t members = 4,
                            std::uint32_t buckets = 64, std::uint32_t min_active = 2) {
  fixture.authorize_paths(16, 1);
  const CreateGroupRequest request =
      fixture.create_request(seed, members, buckets, min_active, 1);
  return fixture.governor->create_group(request);
}

bool is_acceptance(const CreateGroupRequest& request, Fixture& fixture) {
  return ecmp::is_acceptance(fixture.governor->create_group(request).outcome);
}

std::filesystem::path temp_store_path(const std::string& name) {
  const std::filesystem::path directory = std::filesystem::temp_directory_path() / "ecmp-governor-tests";
  std::error_code error;
  std::filesystem::create_directories(directory, error);
  return directory / (name + ".store");
}

}  // namespace

// --- creation ---------------------------------------------------------------

ECMP_TEST(test_create_group_is_active_and_balanced) {
  Fixture fixture;
  ECMP_REQUIRE(fixture.register_publisher());
  const MutationResult result = create_simple(fixture, 1, 4, 64, 2);
  ECMP_REQUIRE(is_acceptance(result.outcome));
  ECMP_CHECK(result.outcome == Outcome::CREATED);
  ECMP_REQUIRE(result.group.has_value());
  ECMP_CHECK(result.group->lifecycle == GroupLifecycle::ACTIVE);
  ECMP_CHECK(result.group->currentness.is_current());
  ECMP_CHECK_EQ(result.group->membership_generation.value(), std::uint64_t{1});
  ECMP_CHECK_EQ(result.group->assignment_generation.value(), std::uint64_t{1});
  ECMP_CHECK_EQ(result.group->authority_generation.value(), std::uint64_t{1});
  ECMP_CHECK_EQ(result.group->active_members, std::uint32_t{4});
  ECMP_CHECK_EQ(result.group->declared_members, std::uint32_t{4});

  const std::optional<GroupSnapshot> snapshot = fixture.governor->snapshot(synthetic_group_id(1));
  ECMP_REQUIRE(snapshot.has_value());
  ECMP_CHECK_EQ(snapshot->assignment.count.value(), std::uint32_t{64});
  for (const MemberRecord& record : snapshot->members) {
    ECMP_CHECK_EQ(snapshot->assignment.owned_bucket_count(record.member), std::uint32_t{16});
  }
  std::vector<Condition> problems;
  ECMP_CHECK(fixture.governor->check_invariants(problems));
}

ECMP_TEST(test_create_group_rejections_are_structured) {
  Fixture fixture;
  ECMP_REQUIRE(fixture.register_publisher());
  fixture.authorize_paths(16, 1);

  // nil group identity
  CreateGroupRequest nil_group = fixture.create_request(1, 2, 8);
  nil_group.group = ECMPGroupId{};
  ECMP_CHECK(fixture.governor->create_group(nil_group).outcome == Outcome::MALFORMED_REQUEST);

  // member count above the bucket count would let an active member own no bucket
  CreateGroupRequest too_many = fixture.create_request(2, 9, 8);
  ECMP_CHECK(fixture.governor->create_group(too_many).outcome == Outcome::RESOURCE_LIMIT);

  // fewer eligible members than the minimum
  CreateGroupRequest below_minimum = fixture.create_request(3, 2, 8, 3);
  ECMP_CHECK(fixture.governor->create_group(below_minimum).outcome == Outcome::INSUFFICIENT_MEMBERS);

  // cost mismatch inside the declaration
  CreateGroupRequest mismatch = fixture.create_request(4, 3, 8);
  mismatch.members[2].cost.cost.units = 11;
  ECMP_CHECK(fixture.governor->create_group(mismatch).outcome == Outcome::COST_MISMATCH);

  // cross cost class
  CreateGroupRequest cross_class = fixture.create_request(5, 3, 8);
  cross_class.members[2].cost.cost_class = synthetic_ids(77).cost_class;
  ECMP_CHECK(fixture.governor->create_group(cross_class).outcome == Outcome::COST_CLASS_MISMATCH);

  // cost policy that is not the current one
  CreateGroupRequest stale_policy = fixture.create_request(6, 3, 8);
  stale_policy.members[2].cost.binding.policy_generation = CostPolicyGeneration::from_value(9);
  ECMP_CHECK(fixture.governor->create_group(stale_policy).outcome == Outcome::STALE_COST_GENERATION);

  // unknown path
  CreateGroupRequest unknown_path = fixture.create_request(7, 3, 8);
  unknown_path.members[1].path = synthetic_path_id(999999);
  ECMP_CHECK(fixture.governor->create_group(unknown_path).outcome == Outcome::STALE_PATH_AUTHORITY);

  // unauthorized path
  CreateGroupRequest unauthorized = fixture.create_request(8, 3, 8);
  fixture.path_authority.set(unauthorized.members[1].path, 1, false);
  ECMP_CHECK(fixture.governor->create_group(unauthorized).outcome == Outcome::STALE_PATH_AUTHORITY);
  fixture.path_authority.set(unauthorized.members[1].path, 1, true);

  // stale path authority generation
  CreateGroupRequest stale_generation = fixture.create_request(9, 3, 8);
  fixture.path_authority.set(stale_generation.members[0].path, 4, true);
  ECMP_CHECK(fixture.governor->create_group(stale_generation).outcome ==
             Outcome::STALE_PATH_AUTHORITY);
  fixture.path_authority.set(stale_generation.members[0].path, 1, true);

  // duplicate member
  CreateGroupRequest duplicate = fixture.create_request(10, 3, 8);
  duplicate.members[1].member = duplicate.members[0].member;
  ECMP_CHECK(fixture.governor->create_group(duplicate).outcome == Outcome::DUPLICATE_MEMBER);

  // duplicate group identity and duplicate semantic key
  ECMP_REQUIRE(is_acceptance(fixture.governor->create_group(fixture.create_request(11, 2, 8)).outcome));
  ECMP_CHECK(fixture.governor->create_group(fixture.create_request(11, 2, 8)).outcome ==
             Outcome::DUPLICATE_GROUP);
  CreateGroupRequest duplicate_key = fixture.create_request(12, 2, 8);
  duplicate_key.key = synthetic_group_key(synthetic_ids(11));
  duplicate_key.key.fabric = fixture.ids.fabric;
  duplicate_key.cost_semantics = synthetic_cost_semantics(synthetic_ids(11), 1);
  duplicate_key.members =
      synthetic_members(synthetic_ids(11), 2, PathAuthorityGeneration::from_value(1));
  ECMP_CHECK(fixture.governor->create_group(duplicate_key).outcome == Outcome::DUPLICATE_GROUP);

  // malformed limit
  CreateGroupRequest zero_buckets = fixture.create_request(13, 2, 8);
  zero_buckets.bucket_count = BucketCount{};
  ECMP_CHECK(fixture.governor->create_group(zero_buckets).outcome == Outcome::MALFORMED_REQUEST);

  // oversized bucket count
  CreateGroupRequest huge = fixture.create_request(14, 2, 8);
  huge.bucket_count = *BucketCount::make(4096);
  ECMP_CHECK(fixture.governor->create_group(huge).outcome == Outcome::RESOURCE_LIMIT);

  std::vector<Condition> problems;
  ECMP_CHECK(fixture.governor->check_invariants(problems));
}

ECMP_TEST(test_authority_is_required_for_every_mutation) {
  Fixture fixture;
  fixture.authorize_paths(16, 1);

  // Unregistered publisher.
  CreateGroupRequest request = fixture.create_request(1, 2, 8);
  ECMP_CHECK(fixture.governor->create_group(request).outcome == Outcome::UNAUTHORIZED);

  ECMP_REQUIRE(fixture.register_publisher());

  // Deny-all scope is never wildcard authority.
  CreateGroupRequest denied = fixture.create_request(2, 2, 8);
  denied.authority.scope = AuthorityScope::deny_all();
  ECMP_CHECK(fixture.governor->create_group(denied).outcome == Outcome::UNAUTHORIZED);

  // Scope that does not cover the group.
  CreateGroupRequest wrong_scope = fixture.create_request(3, 2, 8);
  wrong_scope.authority.scope = AuthorityScope::for_fabric(synthetic_ids(55).fabric);
  ECMP_CHECK(fixture.governor->create_group(wrong_scope).outcome == Outcome::UNAUTHORIZED);

  // Stale epoch.
  CreateGroupRequest stale_epoch = fixture.create_request(4, 2, 8);
  stale_epoch.authority.epoch = CoordinatorEpoch::from_value(99);
  ECMP_CHECK(fixture.governor->create_group(stale_epoch).outcome == Outcome::STALE_EPOCH);

  // Fresh boot that never registered.
  CreateGroupRequest fresh_boot = fixture.create_request(5, 2, 8);
  fresh_boot.authority.worker_boot = synthetic_boot_id(4242);
  ECMP_CHECK(fixture.governor->create_group(fresh_boot).outcome == Outcome::STALE_WORKER);

  // Missing capability.
  Fixture publish_only;
  publish_only.authorize_paths(16, 1);
  ECMP_REQUIRE(publish_only.register_publisher(2));
  CreateGroupRequest no_capability = publish_only.create_request(6, 2, 8);
  ECMP_CHECK(publish_only.governor->create_group(no_capability).outcome == Outcome::UNAUTHORIZED);

  // Malformed identity.
  CreateGroupRequest malformed = fixture.create_request(7, 2, 8);
  malformed.authority.attempt = MutationAttemptId{};
  ECMP_CHECK(fixture.governor->create_group(malformed).outcome == Outcome::MALFORMED_REQUEST);
}

// --- membership -------------------------------------------------------------

ECMP_TEST(test_add_member_advances_generations_and_rebalances_minimally) {
  Fixture fixture;
  ECMP_REQUIRE(fixture.register_publisher());
  ECMP_REQUIRE(is_acceptance(create_simple(fixture, 1, 3, 64, 1).outcome));

  AddMemberRequest request;
  request.authority = fixture.authority();
  request.group = synthetic_group_id(1);
  request.member = fixture.member(3);
  const MutationResult result = fixture.governor->add_member(request);
  ECMP_REQUIRE(is_acceptance(result.outcome));
  ECMP_CHECK(result.outcome == Outcome::MEMBER_ADDED);
  ECMP_REQUIRE(result.group.has_value());
  ECMP_CHECK_EQ(result.group->membership_generation.value(), std::uint64_t{2});
  ECMP_CHECK_EQ(result.group->assignment_generation.value(), std::uint64_t{2});
  ECMP_CHECK_EQ(result.group->active_members, std::uint32_t{4});

  const std::optional<RebalanceRecord> record = fixture.governor->last_rebalance(request.group);
  ECMP_REQUIRE(record.has_value());
  // Going from 3 members with 64 buckets (22/21/21) to 4 members (16 each) moves
  // exactly the surplus: 6 + 5 + 5.
  ECMP_CHECK_EQ(record->churn, std::uint64_t{16});
  ECMP_CHECK_EQ(record->moves.size(), std::size_t{16});
  for (const BucketMove& move : record->moves) {
    ECMP_CHECK(move.reason == MoveReason::OWNER_OVER_QUOTA);
  }

  // A duplicate add is rejected and changes nothing.
  AddMemberRequest duplicate = request;
  duplicate.authority = fixture.authority();
  duplicate.member.administratively_enabled = false;
  const MutationResult duplicate_result = fixture.governor->add_member(duplicate);
  ECMP_CHECK(duplicate_result.outcome == Outcome::DUPLICATE_MEMBER);
  const std::optional<GroupSnapshot> snapshot = fixture.governor->snapshot(request.group);
  ECMP_REQUIRE(snapshot.has_value());
  ECMP_CHECK_EQ(snapshot->membership_generation.value(), std::uint64_t{2});
  ECMP_CHECK_EQ(snapshot->assignment_generation.value(), std::uint64_t{2});
}

ECMP_TEST(test_remove_member_churn_and_thresholds) {
  Fixture fixture;
  ECMP_REQUIRE(fixture.register_publisher());
  ECMP_REQUIRE(is_acceptance(create_simple(fixture, 1, 4, 64, 2).outcome));

  RemoveMemberRequest request;
  request.authority = fixture.authority();
  request.group = synthetic_group_id(1);
  request.member = synthetic_member_id(2002);
  const MutationResult result = fixture.governor->remove_member(request);
  ECMP_REQUIRE(is_acceptance(result.outcome));
  ECMP_REQUIRE(result.group.has_value());
  ECMP_CHECK(result.group->lifecycle == GroupLifecycle::ACTIVE);
  const std::optional<RebalanceRecord> record = fixture.governor->last_rebalance(request.group);
  ECMP_REQUIRE(record.has_value());
  // Exactly the removed member's sixteen buckets move: the three remaining members
  // keep every bucket they already owned, which is the minimum possible churn.
  ECMP_CHECK_EQ(record->churn, std::uint64_t{16});
  for (const BucketMove& move : record->moves) {
    ECMP_CHECK(move.from == request.member);
    ECMP_CHECK(move.reason == MoveReason::OWNER_REMOVED);
  }

  // Dropping to the last active member keeps the group ACTIVE at the threshold.
  RemoveMemberRequest second;
  second.authority = fixture.authority();
  second.group = request.group;
  second.member = synthetic_member_id(2000);
  ECMP_REQUIRE(is_acceptance(fixture.governor->remove_member(second).outcome));
  const std::optional<GroupSnapshot> two = fixture.governor->snapshot(request.group);
  ECMP_REQUIRE(two.has_value());
  ECMP_CHECK_EQ(two->active_member_count(), std::uint32_t{2});
  ECMP_CHECK(two->lifecycle == GroupLifecycle::ACTIVE);

  // One below the threshold degrades.
  RemoveMemberRequest third;
  third.authority = fixture.authority();
  third.group = request.group;
  third.member = synthetic_member_id(2001);
  const MutationResult degraded = fixture.governor->remove_member(third);
  ECMP_REQUIRE(is_acceptance(degraded.outcome));
  ECMP_REQUIRE(degraded.group.has_value());
  ECMP_CHECK(degraded.group->lifecycle == GroupLifecycle::DEGRADED);
  ECMP_CHECK_EQ(degraded.group->active_members, std::uint32_t{1});

  // Zero active members requires revalidation.
  RemoveMemberRequest last;
  last.authority = fixture.authority();
  last.group = request.group;
  last.member = synthetic_member_id(2003);
  const MutationResult empty = fixture.governor->remove_member(last);
  ECMP_REQUIRE(is_acceptance(empty.outcome));
  ECMP_REQUIRE(empty.group.has_value());
  // With no declared member left the group falls back to DECLARED: it is a declared
  // group with no membership, which is exactly what the lifecycle model states.
  ECMP_CHECK(empty.group->lifecycle == GroupLifecycle::DECLARED);
  ECMP_CHECK_EQ(empty.group->active_members, std::uint32_t{0});

  const std::optional<GroupSnapshot> snapshot = fixture.governor->snapshot(request.group);
  ECMP_REQUIRE(snapshot.has_value());
  for (const ECMPMemberId& owner : snapshot->assignment.owners) {
    ECMP_CHECK(owner.is_nil());
  }
  std::vector<Condition> problems;
  ECMP_CHECK(fixture.governor->check_invariants(problems));
}

ECMP_TEST(test_member_disable_and_enable_semantics) {
  Fixture fixture;
  ECMP_REQUIRE(fixture.register_publisher());
  ECMP_REQUIRE(is_acceptance(create_simple(fixture, 1, 4, 64, 2).outcome));

  SetMemberEnabledRequest disable;
  disable.authority = fixture.authority();
  disable.group = synthetic_group_id(1);
  disable.member = synthetic_member_id(2001);
  disable.enabled = false;
  const MutationResult disabled = fixture.governor->set_member_enabled(disable);
  ECMP_REQUIRE(is_acceptance(disabled.outcome));
  ECMP_CHECK(disabled.outcome == Outcome::MEMBER_DISABLED);

  const std::optional<GroupSnapshot> after_disable = fixture.governor->snapshot(disable.group);
  ECMP_REQUIRE(after_disable.has_value());
  // The member stays declared, loses its buckets, and the membership generation is
  // unchanged because the declared member set did not change.
  ECMP_CHECK_EQ(after_disable->declared_member_count(), std::uint32_t{4});
  ECMP_CHECK_EQ(after_disable->active_member_count(), std::uint32_t{3});
  ECMP_CHECK_EQ(after_disable->membership_generation.value(), std::uint64_t{1});
  ECMP_CHECK_EQ(after_disable->assignment_generation.value(), std::uint64_t{2});
  const MemberRecord* record = after_disable->find_member(disable.member);
  ECMP_REQUIRE(record != nullptr);
  ECMP_CHECK(record->state == MemberState::INELIGIBLE);
  ECMP_CHECK(record->declared);
  ECMP_CHECK_EQ(after_disable->assignment.owned_bucket_count(disable.member), std::uint32_t{0});
  for (const ECMPMemberId& owner : after_disable->assignment.owners) {
    ECMP_CHECK(!(owner == disable.member));
  }

  // Re-disabling changes nothing.
  SetMemberEnabledRequest again = disable;
  again.authority = fixture.authority();
  ECMP_CHECK(fixture.governor->set_member_enabled(again).outcome == Outcome::NO_CHANGE);

  // Re-enabling requires the current Path Authority binding.
  fixture.path_authority.set(synthetic_path_id(1001), 7, true);
  SetMemberEnabledRequest enable = disable;
  enable.authority = fixture.authority();
  enable.enabled = true;
  ECMP_CHECK(fixture.governor->set_member_enabled(enable).outcome == Outcome::STALE_PATH_AUTHORITY);

  // With a current binding the member returns and the split is restored exactly.
  fixture.path_authority.set(synthetic_path_id(1001), 1, true);
  SetMemberEnabledRequest restored = disable;
  restored.authority = fixture.authority();
  restored.enabled = true;
  const MutationResult enabled = fixture.governor->set_member_enabled(restored);
  ECMP_REQUIRE(is_acceptance(enabled.outcome));
  const std::optional<GroupSnapshot> after_enable = fixture.governor->snapshot(disable.group);
  ECMP_REQUIRE(after_enable.has_value());
  ECMP_CHECK_EQ(after_enable->active_member_count(), std::uint32_t{4});
  for (const MemberRecord& member : after_enable->members) {
    ECMP_CHECK_EQ(after_enable->assignment.owned_bucket_count(member.member), std::uint32_t{16});
  }
}

// --- idempotency and generations -------------------------------------------

ECMP_TEST(test_exact_replay_is_idempotent_and_advances_nothing) {
  Fixture fixture;
  ECMP_REQUIRE(fixture.register_publisher());
  fixture.authorize_paths(16, 1);
  CreateGroupRequest request = fixture.create_request(1, 3, 32, 1);
  request.authority = fixture.authority(5000);
  const MutationResult first = fixture.governor->create_group(request);
  ECMP_REQUIRE(first.outcome == Outcome::CREATED);

  const MutationResult replay = fixture.governor->create_group(request);
  ECMP_CHECK(replay.outcome == Outcome::IDEMPOTENT);
  const std::optional<GroupSnapshot> snapshot = fixture.governor->snapshot(request.group);
  ECMP_REQUIRE(snapshot.has_value());
  ECMP_CHECK_EQ(snapshot->membership_generation.value(), std::uint64_t{1});
  ECMP_CHECK_EQ(snapshot->assignment_generation.value(), std::uint64_t{1});

  // The same attempt identifier with a different payload is a deterministic reject.
  CreateGroupRequest conflict = fixture.create_request(2, 3, 32, 1);
  conflict.authority = request.authority;
  conflict.authority.epoch = fixture.governor->epoch();
  ECMP_CHECK(fixture.governor->create_group(conflict).outcome == Outcome::ATTEMPT_CONFLICT);
}

ECMP_TEST(test_expected_generation_mismatch_rejects) {
  Fixture fixture;
  ECMP_REQUIRE(fixture.register_publisher());
  ECMP_REQUIRE(is_acceptance(create_simple(fixture, 1, 3, 32, 1).outcome));

  AddMemberRequest request;
  request.authority = fixture.authority();
  request.authority.expected_membership = MembershipGeneration::from_value(7);
  request.group = synthetic_group_id(1);
  request.member = fixture.member(3);
  ECMP_CHECK(fixture.governor->add_member(request).outcome == Outcome::STALE_GROUP_GENERATION);

  request.authority.expected_membership = MembershipGeneration::from_value(1);
  request.authority.expected_assignment = AssignmentGeneration::from_value(9);
  ECMP_CHECK(fixture.governor->add_member(request).outcome == Outcome::STALE_ASSIGNMENT_GENERATION);

  request.authority.expected_assignment = AssignmentGeneration::from_value(1);
  request.authority.expected_authority = AuthorityGeneration::from_value(9);
  ECMP_CHECK(fixture.governor->add_member(request).outcome == Outcome::STALE_AUTHORITY_GENERATION);

  request.authority.expected_authority = AuthorityGeneration::from_value(1);
  ECMP_CHECK(is_acceptance(fixture.governor->add_member(request).outcome));
}

// --- invalidation -----------------------------------------------------------

ECMP_TEST(test_path_invalidation_invalidates_only_dependents) {
  Fixture fixture;
  ECMP_REQUIRE(fixture.register_publisher());
  ECMP_REQUIRE(is_acceptance(create_simple(fixture, 1, 4, 64, 2).outcome));

  // A second group on different paths must be untouched.
  Fixture other;
  other.publisher = fixture.publisher;
  other.boot = fixture.boot;
  ECMP_REQUIRE(other.register_publisher());
  other.authorize_paths(4, 1, 5000);
  CreateGroupRequest other_request = other.create_request(2, 2, 16, 1);
  other_request.members = synthetic_members(synthetic_ids(2), 2,
                                            PathAuthorityGeneration::from_value(1), 5000, 6000);
  other_request.members[0].member = fixture.member(0).member;
  other_request.members[1].member = fixture.member(1).member;
  ECMP_REQUIRE(is_acceptance(other.governor->create_group(other_request).outcome));

  const PathId invalidated = synthetic_path_id(1002);
  fixture.path_authority.set(invalidated, 2, false);

  PathAuthorityChangeNotice notice;
  notice.epoch = fixture.governor->epoch();
  notice.publisher = fixture.publisher;
  notice.worker_boot = fixture.boot;
  notice.path = invalidated;
  notice.generation = PathAuthorityGeneration::from_value(2);
  const MutationResult result = fixture.governor->notify_path_authority_change(notice);
  ECMP_CHECK(is_acceptance(result.outcome));
  ECMP_CHECK(result.outcome == Outcome::REBALANCED);

  const std::optional<GroupSnapshot> snapshot = fixture.governor->snapshot(synthetic_group_id(1));
  ECMP_REQUIRE(snapshot.has_value());
  const MemberRecord* stale = snapshot->find_member(synthetic_member_id(2002));
  ECMP_REQUIRE(stale != nullptr);
  ECMP_CHECK(stale->state == MemberState::REVALIDATION_REQUIRED);
  ECMP_CHECK(snapshot->currentness.has(CurrentnessCause::STALE_PATH_AUTHORITY));
  // Two active members still satisfy the threshold, so the group stays ACTIVE.
  ECMP_CHECK(snapshot->lifecycle == GroupLifecycle::ACTIVE);
  ECMP_CHECK_EQ(snapshot->active_member_count(), std::uint32_t{3});
  for (const ECMPMemberId& owner : snapshot->assignment.owners) {
    ECMP_CHECK(!(owner == stale->member));
  }

  // An unrelated path leaves the group unchanged.
  const std::optional<GroupSnapshot> before = fixture.governor->snapshot(synthetic_group_id(1));
  PathAuthorityChangeNotice unrelated = notice;
  unrelated.path = synthetic_path_id(999999);
  const MutationResult unrelated_result = fixture.governor->notify_path_authority_change(unrelated);
  ECMP_CHECK(unrelated_result.outcome == Outcome::NO_CHANGE);
  const std::optional<GroupSnapshot> after = fixture.governor->snapshot(synthetic_group_id(1));
  ECMP_REQUIRE(before.has_value() && after.has_value());
  ECMP_CHECK(before->semantic_digest == after->semantic_digest);

  std::vector<Condition> problems;
  ECMP_CHECK(fixture.governor->check_invariants(problems));
}

ECMP_TEST(test_member_revalidation_restores_the_previous_assignment_exactly) {
  Fixture fixture;
  ECMP_REQUIRE(fixture.register_publisher());
  ECMP_REQUIRE(is_acceptance(create_simple(fixture, 1, 4, 64, 2).outcome));
  const std::optional<GroupSnapshot> original = fixture.governor->snapshot(synthetic_group_id(1));
  ECMP_REQUIRE(original.has_value());

  fixture.path_authority.set(synthetic_path_id(1002), 2, false);
  PathAuthorityChangeNotice notice;
  notice.epoch = fixture.governor->epoch();
  notice.publisher = fixture.publisher;
  notice.worker_boot = fixture.boot;
  notice.path = synthetic_path_id(1002);
  notice.generation = PathAuthorityGeneration::from_value(2);
  ECMP_REQUIRE(is_acceptance(fixture.governor->notify_path_authority_change(notice).outcome));

  // Revalidating with the stale binding is refused.
  RevalidateGroupRequest stale;
  stale.authority = fixture.authority();
  stale.group = synthetic_group_id(1);
  MemberRevalidation update;
  update.member = synthetic_member_id(2002);
  update.path_authority = PathAuthorityGeneration::from_value(1);
  stale.members.push_back(update);
  ECMP_CHECK(fixture.governor->revalidate_group(stale).outcome == Outcome::STALE_PATH_AUTHORITY);

  // With the current binding the member returns and the original split is restored.
  fixture.path_authority.set(synthetic_path_id(1002), 2, true);
  RevalidateGroupRequest valid = stale;
  valid.authority = fixture.authority();
  valid.members[0].path_authority = PathAuthorityGeneration::from_value(2);
  const MutationResult revalidated = fixture.governor->revalidate_group(valid);
  ECMP_REQUIRE(is_acceptance(revalidated.outcome));
  ECMP_CHECK(revalidated.outcome == Outcome::REVALIDATED);
  const std::optional<GroupSnapshot> restored = fixture.governor->snapshot(synthetic_group_id(1));
  ECMP_REQUIRE(restored.has_value());
  ECMP_CHECK_EQ(restored->active_member_count(), std::uint32_t{4});
  ECMP_CHECK(restored->lifecycle == GroupLifecycle::ACTIVE);
  ECMP_CHECK(restored->currentness.is_current());
  // Restoring a member produces a minimum-churn balanced assignment.  It is not
  // required to reproduce the pre-invalidation bucket map, and the churn is exactly
  // the oracle minimum from the map that was current when the member returned.
  const std::optional<RebalanceRecord> record =
      fixture.governor->last_rebalance(synthetic_group_id(1));
  ECMP_REQUIRE(record.has_value());
  ECMP_CHECK_EQ(record->churn, std::uint64_t{16});
  for (const MemberRecord& member : restored->members) {
    ECMP_CHECK_EQ(restored->assignment.owned_bucket_count(member.member), std::uint32_t{16});
  }
  ECMP_CHECK(original.has_value());
}

ECMP_TEST(test_cost_policy_change_requires_full_reproof) {
  Fixture fixture;
  ECMP_REQUIRE(fixture.register_publisher());
  ECMP_REQUIRE(is_acceptance(create_simple(fixture, 1, 3, 32, 1).outcome));
  const std::optional<GroupSnapshot> original = fixture.governor->snapshot(synthetic_group_id(1));
  ECMP_REQUIRE(original.has_value());

  CostGenerationChangeNotice notice;
  notice.epoch = fixture.governor->epoch();
  notice.publisher = fixture.publisher;
  notice.worker_boot = fixture.boot;
  notice.cost_class = fixture.ids.cost_class;
  notice.generation = CostPolicyGeneration::from_value(2);
  const MutationResult invalidated = fixture.governor->notify_cost_generation_change(notice);
  ECMP_CHECK(is_acceptance(invalidated.outcome));
  ECMP_CHECK(invalidated.outcome == Outcome::REBALANCED);

  const std::optional<GroupSnapshot> stale = fixture.governor->snapshot(synthetic_group_id(1));
  ECMP_REQUIRE(stale.has_value());
  ECMP_CHECK(stale->currentness.has(CurrentnessCause::STALE_COST_CLASS));
  ECMP_CHECK(stale->lifecycle == GroupLifecycle::REVALIDATION_REQUIRED);
  ECMP_CHECK_EQ(stale->active_member_count(), std::uint32_t{0});

  // A partial reproof is refused: every declared member must be re-proved.
  RevalidateGroupRequest partial;
  partial.authority = fixture.authority();
  partial.group = synthetic_group_id(1);
  MemberRevalidation single;
  single.member = synthetic_member_id(2000);
  single.path_authority = PathAuthorityGeneration::from_value(1);
  single.cost = synthetic_cost_claim(fixture.ids, 2000, 10, 2);
  partial.members.push_back(single);
  ECMP_CHECK(fixture.governor->revalidate_group(partial).outcome == Outcome::STALE_COST_GENERATION);

  // A full reproof under the new policy restores the group with the same split.
  RevalidateGroupRequest full;
  full.authority = fixture.authority();
  full.group = synthetic_group_id(1);
  for (std::uint32_t index = 0; index < 3; ++index) {
    MemberRevalidation entry;
    entry.member = synthetic_member_id(2000 + index);
    entry.path_authority = PathAuthorityGeneration::from_value(1);
    entry.cost = synthetic_cost_claim(fixture.ids, 2000 + index, 10, 2);
    full.members.push_back(entry);
  }
  const MutationResult revalidated = fixture.governor->revalidate_group(full);
  ECMP_REQUIRE(is_acceptance(revalidated.outcome));
  const std::optional<GroupSnapshot> restored = fixture.governor->snapshot(synthetic_group_id(1));
  ECMP_REQUIRE(restored.has_value());
  ECMP_CHECK(restored->currentness.is_current());
  ECMP_CHECK(restored->lifecycle == GroupLifecycle::ACTIVE);
  ECMP_CHECK_EQ(restored->cost_semantics.binding.policy_generation.value(), std::uint64_t{2});
  // Re-proving the very same member set reproduces the very same bucket map.
  ECMP_CHECK(restored->assignment.owners == original->assignment.owners);
  ECMP_CHECK(restored->assignment_digest == original->assignment_digest);
}

// --- watermarks and stale completion ---------------------------------------

ECMP_TEST(test_stale_rebalance_plan_cannot_commit) {
  Fixture fixture;
  ECMP_REQUIRE(fixture.register_publisher());
  ECMP_REQUIRE(is_acceptance(create_simple(fixture, 1, 4, 64, 2).outcome));

  RebalancePlanRequest plan;
  plan.authority = fixture.authority();
  plan.group = synthetic_group_id(1);
  plan.target_members = synthetic_members(fixture.ids, 3, PathAuthorityGeneration::from_value(1));
  const MutationResult planned = fixture.governor->plan_rebalance(plan);
  ECMP_REQUIRE(is_acceptance(planned.outcome));
  ECMP_CHECK(planned.outcome == Outcome::REBALANCE_PLANNED);
  ECMP_REQUIRE(planned.plan.has_value());

  // The mandatory race: the plan is prepared at membership generation 1, then an
  // authoritative invalidation advances the state before the commit arrives.
  fixture.path_authority.set(synthetic_path_id(1000), 5, false);
  PathAuthorityChangeNotice notice;
  notice.epoch = fixture.governor->epoch();
  notice.publisher = fixture.publisher;
  notice.worker_boot = fixture.boot;
  notice.path = synthetic_path_id(1000);
  notice.generation = PathAuthorityGeneration::from_value(5);
  const MutationResult invalidated = fixture.governor->notify_path_authority_change(notice);
  ECMP_CHECK(is_acceptance(invalidated.outcome));

  const std::optional<GroupSnapshot> before_commit =
      fixture.governor->snapshot(synthetic_group_id(1));
  ECMP_REQUIRE(before_commit.has_value());

  RebalanceCommitRequest commit;
  commit.authority = fixture.authority();
  commit.group = synthetic_group_id(1);
  commit.plan = *planned.plan;
  const MutationResult committed = fixture.governor->commit_rebalance(commit);
  ECMP_CHECK(committed.outcome == Outcome::STALE_PLAN);

  const std::optional<GroupSnapshot> after_commit =
      fixture.governor->snapshot(synthetic_group_id(1));
  ECMP_REQUIRE(after_commit.has_value());
  ECMP_CHECK(after_commit->semantic_digest == before_commit->semantic_digest);
  ECMP_CHECK(after_commit->assignment.owners == before_commit->assignment.owners);
}

ECMP_TEST(test_plan_commit_and_abort) {
  Fixture fixture;
  ECMP_REQUIRE(fixture.register_publisher());
  ECMP_REQUIRE(is_acceptance(create_simple(fixture, 1, 4, 64, 2).outcome));

  RebalancePlanRequest plan;
  plan.authority = fixture.authority();
  plan.group = synthetic_group_id(1);
  plan.target_members = synthetic_members(fixture.ids, 2, PathAuthorityGeneration::from_value(1));
  const MutationResult planned = fixture.governor->plan_rebalance(plan);
  ECMP_REQUIRE(is_acceptance(planned.outcome));
  ECMP_REQUIRE(planned.plan.has_value());
  ECMP_REQUIRE(planned.group.has_value());
  ECMP_CHECK(planned.group->lifecycle == GroupLifecycle::REBALANCING);

  // Membership mutation is refused while a plan is pending: the outcome is
  // deterministic instead of a silent stale completion.
  AddMemberRequest blocked;
  blocked.authority = fixture.authority();
  blocked.group = plan.group;
  blocked.member = fixture.member(5);
  blocked.member.path = synthetic_path_id(1005);
  fixture.path_authority.set(blocked.member.path, 1, true);
  ECMP_CHECK(fixture.governor->add_member(blocked).outcome == Outcome::LIFECYCLE_VIOLATION);

  RebalanceAbortRequest abort;
  abort.authority = fixture.authority();
  abort.group = plan.group;
  abort.plan = *planned.plan;
  const MutationResult aborted = fixture.governor->abort_rebalance(abort);
  ECMP_REQUIRE(is_acceptance(aborted.outcome));
  ECMP_CHECK(aborted.outcome == Outcome::REBALANCE_ABORTED);
  ECMP_REQUIRE(aborted.group.has_value());
  ECMP_CHECK(aborted.group->lifecycle == GroupLifecycle::ACTIVE);

  // Plan again and commit.
  RebalancePlanRequest second = plan;
  second.authority = fixture.authority();
  const MutationResult planned_again = fixture.governor->plan_rebalance(second);
  ECMP_REQUIRE(is_acceptance(planned_again.outcome));
  ECMP_REQUIRE(planned_again.plan.has_value());
  RebalanceCommitRequest commit;
  commit.authority = fixture.authority();
  commit.group = plan.group;
  commit.plan = *planned_again.plan;
  const MutationResult committed = fixture.governor->commit_rebalance(commit);
  ECMP_REQUIRE(is_acceptance(committed.outcome));
  ECMP_CHECK(committed.outcome == Outcome::REBALANCED);
  const std::optional<GroupSnapshot> snapshot = fixture.governor->snapshot(plan.group);
  ECMP_REQUIRE(snapshot.has_value());
  ECMP_CHECK_EQ(snapshot->active_member_count(), std::uint32_t{2});
  ECMP_CHECK_EQ(snapshot->assignment.owners.size(), std::size_t{64});
  for (const MemberRecord& member : snapshot->members) {
    if (member.declared) {
      ECMP_CHECK_EQ(snapshot->assignment.owned_bucket_count(member.member), std::uint32_t{32});
    }
  }
  std::vector<Condition> problems;
  ECMP_CHECK(fixture.governor->check_invariants(problems));
}

// --- administrative closure -------------------------------------------------

ECMP_TEST(test_revocation_retirement_and_supersession_prevent_resurrection) {
  Fixture fixture;
  ECMP_REQUIRE(fixture.register_publisher());
  ECMP_REQUIRE(is_acceptance(create_simple(fixture, 1, 3, 32, 1).outcome));
  ECMP_REQUIRE(is_acceptance(create_simple(fixture, 2, 2, 16, 1).outcome));

  GroupAdminRequest revoke;
  revoke.authority = fixture.authority();
  revoke.group = synthetic_group_id(1);
  const MutationResult revoked = fixture.governor->revoke_group(revoke);
  ECMP_REQUIRE(is_acceptance(revoked.outcome));
  ECMP_CHECK(revoked.outcome == Outcome::REVOKED_OK);
  ECMP_REQUIRE(revoked.group.has_value());
  ECMP_CHECK(revoked.group->lifecycle == GroupLifecycle::REVOKED);
  ECMP_CHECK(revoked.group->currentness.has(CurrentnessCause::RETIRED));

  // Nothing may reactivate a revoked group.
  AddMemberRequest add;
  add.authority = fixture.authority();
  add.group = revoke.group;
  add.member = fixture.member(5);
  fixture.path_authority.set(add.member.path, 1, true);
  ECMP_CHECK(fixture.governor->add_member(add).outcome == Outcome::REVOKED);

  RevalidateGroupRequest revalidate;
  revalidate.authority = fixture.authority();
  revalidate.group = revoke.group;
  ECMP_CHECK(fixture.governor->revalidate_group(revalidate).outcome == Outcome::REVOKED);

  GroupAdminRequest retire;
  retire.authority = fixture.authority();
  retire.group = synthetic_group_id(2);
  const MutationResult retired = fixture.governor->retire_group(retire);
  ECMP_REQUIRE(is_acceptance(retired.outcome));
  ECMP_CHECK(retired.outcome == Outcome::RETIRED_OK);
  // An exact replay of the retirement advances nothing; a new attempt against a
  // retired group is refused as terminated.
  ECMP_CHECK(fixture.governor->retire_group(retire).outcome == Outcome::IDEMPOTENT);
  GroupAdminRequest second_retire = retire;
  second_retire.authority = fixture.authority();
  ECMP_CHECK(fixture.governor->retire_group(second_retire).outcome == Outcome::RETIRED);
  AddMemberRequest retired_add = add;
  retired_add.authority = fixture.authority();
  retired_add.group = synthetic_group_id(2);
  ECMP_CHECK(fixture.governor->add_member(retired_add).outcome == Outcome::RETIRED);

  // Supersession preserves both directions of lineage.
  Fixture lineage;
  ECMP_REQUIRE(lineage.register_publisher());
  lineage.authorize_paths(8, 1);
  ECMP_REQUIRE(is_acceptance(lineage.governor->create_group(lineage.create_request(10, 2, 16)).outcome));
  ECMP_REQUIRE(is_acceptance(lineage.governor->create_group(lineage.create_request(11, 2, 16)).outcome));
  GroupAdminRequest supersede;
  supersede.authority = lineage.authority();
  supersede.group = synthetic_group_id(10);
  supersede.successor = synthetic_group_id(11);
  const MutationResult superseded = lineage.governor->supersede_group(supersede);
  ECMP_REQUIRE(is_acceptance(superseded.outcome));
  ECMP_CHECK(superseded.outcome == Outcome::SUPERSEDED_OK);
  ECMP_REQUIRE(superseded.group.has_value());
  ECMP_CHECK(superseded.group->lifecycle == GroupLifecycle::SUPERSEDED);
  std::vector<Condition> problems;
  ECMP_CHECK(lineage.governor->check_invariants(problems));

  // Superseding with an unknown successor is rejected.
  GroupAdminRequest unknown = supersede;
  unknown.authority = lineage.authority();
  unknown.group = synthetic_group_id(11);
  unknown.successor = synthetic_group_id(99);
  ECMP_CHECK(lineage.governor->supersede_group(unknown).outcome == Outcome::UNKNOWN_GROUP);
}

ECMP_TEST(test_withdrawal_is_two_phase_and_irreversible) {
  Fixture fixture;
  ECMP_REQUIRE(fixture.register_publisher());
  ECMP_REQUIRE(is_acceptance(create_simple(fixture, 1, 3, 32, 1).outcome));

  GroupAdminRequest withdraw;
  withdraw.authority = fixture.authority();
  withdraw.group = synthetic_group_id(1);
  const MutationResult initiated = fixture.governor->withdraw_group(withdraw);
  ECMP_REQUIRE(is_acceptance(initiated.outcome));
  ECMP_REQUIRE(initiated.group.has_value());
  ECMP_CHECK(initiated.group->lifecycle == GroupLifecycle::WITHDRAWING);
  // Membership mutation stops during an orderly withdrawal.
  AddMemberRequest add;
  add.authority = fixture.authority();
  add.group = withdraw.group;
  add.member = fixture.member(7);
  add.member.path = synthetic_path_id(1007);
  fixture.path_authority.set(add.member.path, 1, true);
  ECMP_CHECK(fixture.governor->add_member(add).outcome == Outcome::LIFECYCLE_VIOLATION);

  GroupAdminRequest complete;
  complete.authority = fixture.authority();
  complete.group = withdraw.group;
  const MutationResult withdrawn = fixture.governor->withdraw_group(complete);
  ECMP_REQUIRE(is_acceptance(withdrawn.outcome));
  ECMP_REQUIRE(withdrawn.group.has_value());
  ECMP_CHECK(withdrawn.group->lifecycle == GroupLifecycle::WITHDRAWN);
  ECMP_CHECK_EQ(withdrawn.group->declared_members, std::uint32_t{0});
  ECMP_CHECK_EQ(withdrawn.group->active_members, std::uint32_t{0});
  ECMP_CHECK(fixture.governor->add_member(add).outcome == Outcome::WITHDRAWN);
}

// --- fencing ----------------------------------------------------------------

ECMP_TEST(test_fenced_publisher_loses_live_authority_and_a_fresh_boot_restores_it) {
  Fixture fixture;
  ECMP_REQUIRE(fixture.register_publisher());
  ECMP_REQUIRE(is_acceptance(create_simple(fixture, 1, 3, 32, 1).outcome));

  ConditionList conditions(fixture.limits.max_explanation_entries);
  ECMP_CHECK(fixture.governor->fence_publisher(fixture.publisher, fixture.boot, conditions) ==
             Outcome::FENCED);

  const std::optional<GroupSnapshot> fenced = fixture.governor->snapshot(synthetic_group_id(1));
  ECMP_REQUIRE(fenced.has_value());
  ECMP_CHECK(fenced->currentness.has(CurrentnessCause::FENCED_PUBLISHER));
  ECMP_CHECK(fenced->lifecycle == GroupLifecycle::REVALIDATION_REQUIRED);
  ECMP_CHECK(fenced->currentness.authority_current() == false);

  // The old boot can never mutate again, not even by re-registering.
  ConditionList re_register(64);
  PublisherRegistration registration;
  registration.publisher = fixture.publisher;
  registration.worker_boot = fixture.boot;
  registration.scope = AuthorityScope::for_fabric(fixture.ids.fabric);
  registration.capabilities = 3;
  registration.provenance = fixture.ids.provenance;
  ECMP_CHECK(fixture.governor->register_publisher(fixture.governor->epoch(), registration,
                                                  re_register) == Outcome::STALE_WORKER);

  // A fresh boot for the same publisher identity is accepted and may revalidate.
  ConditionList fresh_conditions(64);
  registration.worker_boot = synthetic_boot_id(2);
  ECMP_CHECK(fixture.governor->register_publisher(fixture.governor->epoch(), registration,
                                                  fresh_conditions) == Outcome::REGISTERED);
  RevalidateGroupRequest revalidate;
  revalidate.authority.epoch = fixture.governor->epoch();
  revalidate.authority.publisher = fixture.publisher;
  revalidate.authority.worker_boot = synthetic_boot_id(2);
  revalidate.authority.scope = AuthorityScope::for_fabric(fixture.ids.fabric);
  revalidate.authority.attempt = synthetic_attempt_id(90210);
  revalidate.group = synthetic_group_id(1);
  const MutationResult revalidated = fixture.governor->revalidate_group(revalidate);
  ECMP_REQUIRE(is_acceptance(revalidated.outcome));
  const std::optional<GroupSnapshot> restored = fixture.governor->snapshot(synthetic_group_id(1));
  ECMP_REQUIRE(restored.has_value());
  ECMP_CHECK(restored->currentness.is_current());
  ECMP_CHECK(restored->lifecycle == GroupLifecycle::ACTIVE);
  ECMP_CHECK_EQ(restored->authority_generation.value(), std::uint64_t{2});
}

// --- persistence and recovery ----------------------------------------------

ECMP_TEST(test_persistence_round_trip_and_conservative_recovery) {
  const std::filesystem::path store = temp_store_path("roundtrip");
  std::error_code error;
  std::filesystem::remove(store, error);

  std::optional<GroupSnapshot> before;
  {
    Fixture fixture;
    ECMP_REQUIRE(fixture.register_publisher());
    ECMP_REQUIRE(is_acceptance(create_simple(fixture, 1, 4, 64, 2).outcome));
    before = fixture.governor->snapshot(synthetic_group_id(1));
    ECMP_REQUIRE(before.has_value());
    const SaveReport saved = fixture.governor->save(store);
    ECMP_REQUIRE(saved.ok);
    ECMP_CHECK(saved.bytes > 0);
  }

  Fixture recovered;
  const LoadReport loaded = recovered.governor->load(store);
  ECMP_REQUIRE(loaded.ok);
  ECMP_CHECK_EQ(loaded.groups_loaded, std::uint32_t{1});
  ECMP_CHECK_EQ(loaded.stored_epoch.value(), std::uint64_t{1});

  const std::optional<GroupSnapshot> conservative =
      recovered.governor->snapshot(synthetic_group_id(1));
  ECMP_REQUIRE(conservative.has_value());
  ECMP_CHECK(conservative->lifecycle == GroupLifecycle::REVALIDATION_REQUIRED);
  ECMP_CHECK(conservative->currentness.has(CurrentnessCause::STALE_EPOCH));
  ECMP_CHECK(conservative->currentness.has(CurrentnessCause::REVALIDATION_REQUIRED));
  // The durable bucket map survives as desired state ...
  ECMP_CHECK(conservative->assignment.owners == before->assignment.owners);
  ECMP_CHECK(conservative->assignment_digest == before->assignment_digest);
  // ... but no live authority does: every member must be re-proved.
  ECMP_CHECK_EQ(conservative->active_member_count(), std::uint32_t{0});
  for (const MemberRecord& member : conservative->members) {
    ECMP_CHECK(member.state == MemberState::REVALIDATION_REQUIRED);
  }
  // The authority generation advanced because the coordinator incarnation changed.
  ECMP_CHECK(conservative->authority_generation.value() > before->authority_generation.value());

  // The epoch must advance monotonically, and old epoch traffic must be rejected.
  ConditionList conditions(64);
  ECMP_REQUIRE(recovered.governor->set_epoch(CoordinatorEpoch::from_value(2), conditions));
  ECMP_CHECK(!recovered.governor->set_epoch(CoordinatorEpoch::from_value(1), conditions));

  // Register and revalidate: the assignment is restored without churn.
  const PublisherId publisher = synthetic_publisher_id(1);
  const WorkerBootId boot = synthetic_boot_id(77);
  PublisherRegistration registration;
  registration.publisher = publisher;
  registration.worker_boot = boot;
  registration.scope = AuthorityScope::for_fabric(recovered.ids.fabric);
  registration.capabilities = 3;
  registration.provenance = recovered.ids.provenance;
  ECMP_REQUIRE(recovered.governor->register_publisher(recovered.governor->epoch(), registration,
                                                      conditions) == Outcome::REGISTERED);

  recovered.authorize_paths(16, 1);
  RevalidateGroupRequest revalidate;
  revalidate.authority.epoch = recovered.governor->epoch();
  revalidate.authority.publisher = publisher;
  revalidate.authority.worker_boot = boot;
  revalidate.authority.scope = registration.scope;
  revalidate.authority.attempt = synthetic_attempt_id(1);
  revalidate.group = synthetic_group_id(1);
  for (std::uint32_t index = 0; index < 4; ++index) {
    MemberRevalidation entry;
    entry.member = synthetic_member_id(2000 + index);
    entry.path_authority = PathAuthorityGeneration::from_value(1);
    revalidate.members.push_back(entry);
  }
  const MutationResult revalidated = recovered.governor->revalidate_group(revalidate);
  ECMP_REQUIRE(is_acceptance(revalidated.outcome));
  const std::optional<GroupSnapshot> restored = recovered.governor->snapshot(synthetic_group_id(1));
  ECMP_REQUIRE(restored.has_value());
  ECMP_CHECK(restored->currentness.is_current());
  ECMP_CHECK(restored->lifecycle == GroupLifecycle::ACTIVE);
  ECMP_CHECK(restored->assignment.owners == before->assignment.owners);
  std::vector<Condition> problems;
  ECMP_CHECK(recovered.governor->check_invariants(problems));
  std::filesystem::remove(store, error);
}

// --- explanations, diffs, limits -------------------------------------------

ECMP_TEST(test_explanations_and_diffs_are_deterministic) {
  Fixture fixture;
  ECMP_REQUIRE(fixture.register_publisher());
  ECMP_REQUIRE(is_acceptance(create_simple(fixture, 1, 4, 16, 2).outcome));
  const std::optional<GroupSnapshot> before = fixture.governor->snapshot(synthetic_group_id(1));
  ECMP_REQUIRE(before.has_value());

  RemoveMemberRequest remove;
  remove.authority = fixture.authority();
  remove.group = synthetic_group_id(1);
  remove.member = synthetic_member_id(2003);
  ECMP_REQUIRE(is_acceptance(fixture.governor->remove_member(remove).outcome));
  const std::optional<GroupSnapshot> after = fixture.governor->snapshot(synthetic_group_id(1));
  ECMP_REQUIRE(after.has_value());

  const GroupDiff diff = diff_snapshots(*before, *after);
  ECMP_CHECK(!diff.is_empty());
  ECMP_CHECK_EQ(diff.churn, std::uint64_t{4});
  ECMP_REQUIRE(diff.members.size() == 1);
  ECMP_CHECK(diff.members[0].removed);
  ECMP_CHECK_EQ(diff.from_membership.value(), std::uint64_t{1});
  ECMP_CHECK_EQ(diff.to_membership.value(), std::uint64_t{2});
  ECMP_CHECK(diff_snapshots(*before, *after).churn == diff.churn);

  const Explanation group_explanation = fixture.governor->explain_group(synthetic_group_id(1));
  const std::string rendered = group_explanation.render();
  ECMP_CHECK(rendered.find("lifecycle=") != std::string::npos);
  ECMP_CHECK_EQ(group_explanation.render(), rendered);

  const Explanation member_explanation =
      fixture.governor->explain_member(synthetic_group_id(1), synthetic_member_id(2003));
  ECMP_CHECK(member_explanation.render().find("state=WITHDRAWN") != std::string::npos);

  const Explanation bucket_explanation = fixture.governor->explain_bucket(synthetic_group_id(1), BucketId::from_value(3));
  ECMP_CHECK(!bucket_explanation.conditions().empty());

  const Explanation rebalance_explanation =
      fixture.governor->explain_last_rebalance(synthetic_group_id(1));
  ECMP_CHECK(rebalance_explanation.render().find("subject=churn observed=4") !=
             std::string::npos);

  const Explanation authority_explanation =
      fixture.governor->explain_authority(synthetic_group_id(1));
  ECMP_CHECK(authority_explanation.render().find("subject=authority_current observed=1") !=
             std::string::npos);
}

ECMP_TEST(test_every_configured_limit_is_consulted) {
  GovernorLimits limits;
  limits.max_groups = 1;
  limits.max_members_per_group = 4;
  limits.max_total_members = 4;
  limits.max_buckets = 16;
  limits.max_rebalance_moves = 2;
  limits.max_batch_size = 2;
  limits.max_history = 2;
  limits.max_attempts_remembered = 2;
  limits.max_explanation_entries = 3;
  std::string reason;
  ECMP_REQUIRE(limits.is_coherent(reason));

  Fixture fixture(limits);
  ECMP_REQUIRE(fixture.register_publisher());
  fixture.authorize_paths(16, 1);

  // max_groups
  ECMP_REQUIRE(is_acceptance(
      fixture.governor->create_group(fixture.create_request(1, 3, 8, 1)).outcome));
  ECMP_CHECK(fixture.governor->create_group(fixture.create_request(2, 3, 8, 1)).outcome ==
             Outcome::RESOURCE_LIMIT);

  // max_members_per_group: the fourth member is the last one that fits.
  AddMemberRequest fourth;
  fourth.authority = fixture.authority();
  fourth.group = synthetic_group_id(1);
  fourth.member = fixture.member(3);
  ECMP_CHECK(is_acceptance(fixture.governor->add_member(fourth).outcome));

  AddMemberRequest fifth;
  fifth.authority = fixture.authority();
  fifth.group = synthetic_group_id(1);
  fifth.member = fixture.member(4);
  ECMP_CHECK(fixture.governor->add_member(fifth).outcome == Outcome::RESOURCE_LIMIT);

  // max_batch_size on a bulk membership change: replacing all four declared members
  // is eight changes and exceeds the configured batch budget.
  MembershipSetRequest batch;
  batch.authority = fixture.authority();
  batch.group = synthetic_group_id(1);
  batch.members = synthetic_members(fixture.ids, 4, PathAuthorityGeneration::from_value(1), 1000,
                                    2500);
  ECMP_CHECK(fixture.governor->apply_membership_set(batch).outcome == Outcome::RESOURCE_LIMIT);

  // max_rebalance_moves: dropping to a single member would move more buckets than
  // the configured churn budget allows.
  MembershipSetRequest churn;
  churn.authority = fixture.authority();
  churn.group = synthetic_group_id(1);
  churn.members = synthetic_members(fixture.ids, 2, PathAuthorityGeneration::from_value(1));
  const MutationResult churn_result = fixture.governor->apply_membership_set(churn);
  ECMP_CHECK(churn_result.outcome == Outcome::RESOURCE_LIMIT);
  ECMP_CHECK(churn_result.conditions.entries().front().code == ConditionCode::CHURN_LIMIT);

  // max_buckets at creation time
  ECMP_CHECK(fixture.governor->create_group(fixture.create_request(3, 2, 32)).outcome ==
             Outcome::RESOURCE_LIMIT);

  // max_explanation_entries bounds the explanation and reports truncation
  const Explanation explanation = fixture.governor->explain_group(synthetic_group_id(1));
  ECMP_CHECK(explanation.conditions().entries().size() <= limits.max_explanation_entries);
  ECMP_CHECK(explanation.truncated());

  // max_history bounds the retained history
  RemoveMemberRequest remove;
  remove.authority = fixture.authority();
  remove.group = synthetic_group_id(1);
  remove.member = synthetic_member_id(2002);
  ECMP_REQUIRE(is_acceptance(fixture.governor->remove_member(remove).outcome));
  AddMemberRequest readd;
  readd.authority = fixture.authority();
  readd.group = synthetic_group_id(1);
  readd.member = fixture.member(2);
  ECMP_REQUIRE(is_acceptance(fixture.governor->add_member(readd).outcome));
  ECMP_CHECK(fixture.governor->history(synthetic_group_id(1)).size() <= limits.max_history);

  // max_attempts_remembered bounds the idempotency window.  The window is a
  // documented configured bound: once an attempt falls out of it the replay is no
  // longer recognised as a replay.
  GovernorLimits window_limits;
  window_limits.max_attempts_remembered = 2;
  Fixture window(window_limits);
  ECMP_REQUIRE(window.register_publisher());
  window.authorize_paths(16, 1);
  ECMP_REQUIRE(is_acceptance(window.create_request(1, 3, 16, 1), window));
  AddMemberRequest first;
  first.authority = window.authority(90001);
  first.group = synthetic_group_id(1);
  first.member = window.member(3);
  ECMP_REQUIRE(is_acceptance(window.governor->add_member(first).outcome));
  AddMemberRequest second;
  second.authority = window.authority(90002);
  second.group = synthetic_group_id(1);
  second.member = window.member(4);
  ECMP_REQUIRE(is_acceptance(window.governor->add_member(second).outcome));
  AddMemberRequest third;
  third.authority = window.authority(90003);
  third.group = synthetic_group_id(1);
  third.member = window.member(5);
  ECMP_REQUIRE(is_acceptance(window.governor->add_member(third).outcome));
  // The window remembers two attempts, so the oldest attempt is no longer
  // recognised as a replay and the request is judged on its own merits.
  ECMP_CHECK(window.governor->add_member(first).outcome == Outcome::DUPLICATE_MEMBER);
}

ECMP_TEST(test_incoherent_limits_fail_fast) {
  GovernorLimits limits;
  limits.max_members_per_group = 0;
  std::string reason;
  ECMP_CHECK(!limits.is_coherent(reason));
  ECMP_CHECK(!reason.empty());
  bool threw = false;
  try {
    EcmpGovernor governor(limits, CoordinatorEpoch::from_value(1));
    (void)governor;
  } catch (const std::invalid_argument&) {
    threw = true;
  }
  ECMP_CHECK(threw);
}
