// ECMP Governor 1.0.0 - public API examples.
//
// Every scenario below uses only the installed public headers and the exported
// library target.  All identities, costs and paths are SYNTHETIC fixtures derived
// from seeds: nothing here claims physical switch programming, real traffic
// balancing, congestion adaptation or a real fabric.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <string>
#include <vector>

#include "ecmp/ecmp.hpp"

namespace {

using namespace ecmp;

int g_failures = 0;

std::string first_condition(const MutationResult& result) {
  if (result.conditions.empty()) {
    return "none";
  }
  return std::string(to_string(result.conditions.entries().front().code));
}

void expect(bool condition, const char* description) {
  if (!condition) {
    ++g_failures;
    std::printf("  FAILED: %s\n", description);
  }
}

class AuthorizedPaths final : public IPathAuthorityView {
 public:
  std::map<PathId, PathAuthorityObservation> paths;

  [[nodiscard]] std::optional<PathAuthorityObservation> observe(
      const PathId& path) const override {
    const auto it = paths.find(path);
    if (it == paths.end()) {
      return std::nullopt;
    }
    return it->second;
  }

  void authorize(std::uint64_t path_seed, std::uint64_t generation, bool authorized = true) {
    PathAuthorityObservation observation;
    observation.generation = PathAuthorityGeneration::from_value(generation);
    observation.authorized = authorized;
    paths[synthetic_path_id(path_seed)] = observation;
  }

  void authorize_range(std::uint32_t count, std::uint64_t generation, std::uint64_t base) {
    for (std::uint32_t index = 0; index < count; ++index) {
      authorize(base + index, generation);
    }
  }
};

class Example {
 public:
  Example(std::uint64_t seed, std::uint32_t path_base)
      : ids_(synthetic_ids(seed)), path_base_(path_base) {
    PublisherRegistration registration;
    registration.publisher = publisher_;
    registration.worker_boot = boot_;
    registration.scope = AuthorityScope::for_fabric(ids_.fabric);
    registration.capabilities = 3;
    registration.provenance = ids_.provenance;
    ConditionList conditions(limits_.max_explanation_entries);
    const Outcome outcome = governor_.register_publisher(governor_.epoch(), registration, conditions);
    expect(is_acceptance(outcome), "publisher registration");
  }

  [[nodiscard]] EcmpGovernor& governor() { return governor_; }
  [[nodiscard]] const SyntheticIds& ids() const { return ids_; }
  [[nodiscard]] AuthorizedPaths& paths() { return paths_; }
  [[nodiscard]] std::uint32_t path_base() const { return path_base_; }

  AuthorityContext authority() {
    AuthorityContext context;
    context.epoch = governor_.epoch();
    context.publisher = publisher_;
    context.worker_boot = boot_;
    context.scope = AuthorityScope::for_fabric(ids_.fabric);
    context.attempt = synthetic_attempt_id(++attempts_);
    return context;
  }

  CreateGroupRequest create_request(std::uint64_t group_seed, std::uint32_t members,
                                    std::uint32_t buckets, std::uint32_t min_active = 1) {
    CreateGroupRequest request;
    request.authority = authority();
    request.group = synthetic_group_id(group_seed);
    request.key = synthetic_group_key(ids_);
    request.cost_semantics = synthetic_cost_semantics(ids_, 1);
    request.hash_domain = ids_.hash_domain;
    request.provenance = ids_.provenance;
    request.bucket_count = *BucketCount::make(buckets);
    request.min_active_members = min_active;
    request.members = synthetic_members(ids_, members, PathAuthorityGeneration::from_value(1),
                                        path_base_, 2000);
    return request;
  }

  MemberSpec member(std::uint32_t index) {
    return synthetic_member_spec(ids_, 2000 + index, path_base_ + index,
                                 PathAuthorityGeneration::from_value(1));
  }

 private:
  GovernorLimits limits_;
  SyntheticIds ids_;
  AuthorizedPaths paths_;
  PublisherId publisher_ = synthetic_publisher_id(1);
  WorkerBootId boot_ = synthetic_boot_id(1);
  std::uint32_t path_base_ = 1000;
  std::uint64_t attempts_ = 0;
  EcmpGovernor governor_{limits_, CoordinatorEpoch::from_value(1), &paths_, nullptr};
};

void example_two_way_ecmp() {
  std::printf("example: two-way equal-cost ECMP\n");
  Example example(1, 1000);
  example.paths().authorize_range(4, 1, 1000);

  const MutationResult result =
      example.governor().create_group(example.create_request(1, 2, 8, 1));
  expect(is_acceptance(result.outcome), "two-way group created");
  expect(result.group.has_value(), "summary returned");
  expect(result.group->lifecycle == GroupLifecycle::ACTIVE, "lifecycle ACTIVE");
  expect(result.group->active_members == 2, "two active members");

  const std::optional<GroupSnapshot> snapshot = example.governor().snapshot(synthetic_group_id(1));
  expect(snapshot.has_value(), "snapshot available");
  expect(snapshot->assignment.owned_bucket_count(synthetic_member_id(2000)) == 4, "member A owns 4");
  expect(snapshot->assignment.owned_bucket_count(synthetic_member_id(2001)) == 4, "member B owns 4");
  std::printf("  group=%s active=%u buckets=%u\n", result.group->id.to_text().c_str(),
              result.group->active_members, result.group->bucket_count.value());
}

void example_three_way_ecmp() {
  std::printf("example: three-way equal-cost ECMP\n");
  Example example(2, 2000);
  example.paths().authorize_range(4, 1, 2000);

  const MutationResult result =
      example.governor().create_group(example.create_request(1, 3, 8, 1));
  expect(is_acceptance(result.outcome), "three-way group created");
  const std::optional<GroupSnapshot> snapshot = example.governor().snapshot(synthetic_group_id(1));
  expect(snapshot.has_value(), "snapshot available");
  expect(snapshot->assignment.owned_bucket_count(synthetic_member_id(2000)) == 3, "A owns 3");
  expect(snapshot->assignment.owned_bucket_count(synthetic_member_id(2001)) == 3, "B owns 3");
  expect(snapshot->assignment.owned_bucket_count(synthetic_member_id(2002)) == 2, "C owns 2");
  std::printf("  8 buckets split 3/3/2 with canonical tie-break\n");
}

void example_deterministic_bucket_split() {
  std::printf("example: deterministic bucket split\n");
  Example first(3, 3000);
  Example second(3, 3000);
  first.paths().authorize_range(4, 1, 3000);
  second.paths().authorize_range(4, 1, 3000);

  // The same declaration presented in a different order must produce the same
  // canonical membership, digest and bucket map.
  CreateGroupRequest ordered = first.create_request(1, 4, 64, 2);
  CreateGroupRequest shuffled = second.create_request(1, 4, 64, 2);
  std::swap(shuffled.members[0], shuffled.members[3]);
  std::swap(shuffled.members[1], shuffled.members[2]);

  const MutationResult first_result = first.governor().create_group(ordered);
  const MutationResult second_result = second.governor().create_group(shuffled);
  expect(is_acceptance(first_result.outcome), "first group created");
  expect(is_acceptance(second_result.outcome), "second group created");
  expect(first_result.group->semantic_digest == second_result.group->semantic_digest,
         "identical semantic digest");
  expect(first_result.group->assignment_digest == second_result.group->assignment_digest,
         "identical assignment digest");
  std::printf("  semantic_digest=%s\n", first_result.group->semantic_digest.to_text().c_str());
}

void example_member_removal() {
  std::printf("example: member removal with minimum churn\n");
  Example example(4, 4000);
  example.paths().authorize_range(4, 1, 4000);
  expect(is_acceptance(example.governor().create_group(example.create_request(1, 4, 64, 2)).outcome),
         "group created");

  RemoveMemberRequest request;
  request.authority = example.authority();
  request.group = synthetic_group_id(1);
  request.member = synthetic_member_id(2003);
  const MutationResult result = example.governor().remove_member(request);
  expect(is_acceptance(result.outcome), "member removed");
  expect(result.group->active_members == 3, "three active members");

  const std::optional<RebalanceRecord> record = example.governor().last_rebalance(request.group);
  expect(record.has_value(), "rebalance recorded");
  expect(record->churn == 16, "exactly the removed member's buckets moved");
  expect(result.group->assignment_generation.value() == 2, "assignment generation advanced once");
  std::printf("  churn=%llu moves=%zu\n", static_cast<unsigned long long>(record->churn),
              record->moves.size());
}

void example_member_restoration() {
  std::printf("example: member restoration after revalidation\n");
  Example example(5, 5000);
  example.paths().authorize_range(4, 1, 5000);
  expect(is_acceptance(example.governor().create_group(example.create_request(1, 4, 64, 2)).outcome),
         "group created");

  SetMemberEnabledRequest disable;
  disable.authority = example.authority();
  disable.group = synthetic_group_id(1);
  disable.member = synthetic_member_id(2002);
  disable.enabled = false;
  expect(is_acceptance(example.governor().set_member_enabled(disable).outcome), "member disabled");
  const std::optional<GroupSnapshot> disabled = example.governor().snapshot(disable.group);
  expect(disabled.has_value() && disabled->active_member_count() == 3, "three active members");
  expect(disabled->membership_generation.value() == 1, "membership generation unchanged");

  SetMemberEnabledRequest enable = disable;
  enable.authority = example.authority();
  enable.enabled = true;
  expect(is_acceptance(example.governor().set_member_enabled(enable).outcome), "member enabled");
  const std::optional<GroupSnapshot> restored = example.governor().snapshot(disable.group);
  expect(restored.has_value() && restored->active_member_count() == 4, "four active members");
  for (const MemberRecord& record : restored->members) {
    expect(restored->assignment.owned_bucket_count(record.member) == 16, "balanced again");
  }
  std::printf("  active=4 balanced=16/16/16/16\n");
}

void example_stale_path_authority_rejection() {
  std::printf("example: stale Path Authority rejection\n");
  Example example(6, 6000);
  example.paths().authorize_range(4, 1, 6000);
  expect(is_acceptance(example.governor().create_group(example.create_request(1, 3, 32, 1)).outcome),
         "group created");

  // The Path Authority domain advances the generation of one path.
  example.paths().authorize(6001, 2);
  PathAuthorityChangeNotice notice;
  notice.epoch = example.governor().epoch();
  notice.publisher = synthetic_publisher_id(1);
  notice.worker_boot = synthetic_boot_id(1);
  notice.path = synthetic_path_id(6001);
  notice.generation = PathAuthorityGeneration::from_value(2);
  const MutationResult invalidated = example.governor().notify_path_authority_change(notice);
  expect(is_acceptance(invalidated.outcome), "invalidation accepted");

  const std::optional<GroupSnapshot> snapshot = example.governor().snapshot(synthetic_group_id(1));
  expect(snapshot.has_value(), "snapshot available");
  const MemberRecord* stale = snapshot->find_member(synthetic_member_id(2001));
  expect(stale != nullptr, "the invalidated member is still declared");
  if (stale != nullptr) {
    expect(stale->state == MemberState::REVALIDATION_REQUIRED, "member requires revalidation");
    expect(snapshot->assignment.owned_bucket_count(stale->member) == 0,
           "stale member owns no bucket");
  }

  // An add that carries the stale binding is refused rather than silently accepted.
  AddMemberRequest add;
  add.authority = example.authority();
  add.group = synthetic_group_id(1);
  // The declaration still carries generation 1 while the Path Authority domain
  // already reports generation 2, so the binding is stale and must be refused.
  add.member = synthetic_member_spec(example.ids(), 2003, 6003,
                                     PathAuthorityGeneration::from_value(1));
  example.paths().authorize(6003, 2);
  const MutationResult rejected = example.governor().add_member(add);
  expect(rejected.outcome == Outcome::STALE_PATH_AUTHORITY, "stale add rejected");
  std::printf("  outcome=%s condition=%s\n", std::string(to_string(rejected.outcome)).c_str(),
              first_condition(rejected).c_str());
}

void example_cost_mismatch_rejection() {
  std::printf("example: equal-cost mismatch rejection\n");
  Example example(7, 7000);
  example.paths().authorize_range(4, 1, 7000);
  expect(is_acceptance(example.governor().create_group(example.create_request(1, 3, 32, 1)).outcome),
         "group created");

  AddMemberRequest add;
  add.authority = example.authority();
  add.group = synthetic_group_id(1);
  add.member = synthetic_member_spec(example.ids(), 2003, 7003,
                                     PathAuthorityGeneration::from_value(1), 11);
  const MutationResult rejected = example.governor().add_member(add);
  expect(rejected.outcome == Outcome::COST_MISMATCH, "unequal cost rejected");
  const std::optional<GroupSnapshot> snapshot = example.governor().snapshot(synthetic_group_id(1));
  expect(snapshot.has_value() && snapshot->active_member_count() == 3,
         "membership unchanged by the rejection");
  std::printf("  outcome=%s condition=%s\n", std::string(to_string(rejected.outcome)).c_str(),
              first_condition(rejected).c_str());
}

}  // namespace

int main() {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  example_two_way_ecmp();
  example_three_way_ecmp();
  example_deterministic_bucket_split();
  example_member_removal();
  example_member_restoration();
  example_stale_path_authority_rejection();
  example_cost_mismatch_rejection();
  if (g_failures != 0) {
    std::printf("examples failed: %d\n", g_failures);
    return 1;
  }
  std::printf("all API examples completed successfully\n");
  return 0;
}
