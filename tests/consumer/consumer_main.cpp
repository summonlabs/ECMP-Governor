// Independent downstream consumer of the installed ECMP Governor package.
//
// The contract of this program is exactly the one an installer must satisfy:
// find the package, compile, link, create a synthetic ECMP group, add three
// equal-cost path members, verify the deterministic bucket assignment, remove one
// member, verify the deterministic rebalance, and exit successfully.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <map>
#include <optional>

#include <ecmp/ecmp.hpp>

namespace {

class AuthorizedPaths final : public ecmp::IPathAuthorityView {
 public:
  std::map<ecmp::PathId, ecmp::PathAuthorityObservation> paths;

  [[nodiscard]] std::optional<ecmp::PathAuthorityObservation> observe(
      const ecmp::PathId& path) const override {
    const auto it = paths.find(path);
    if (it == paths.end()) {
      return std::nullopt;
    }
    return it->second;
  }

  void authorize(std::uint64_t seed) {
    ecmp::PathAuthorityObservation observation;
    observation.generation = ecmp::PathAuthorityGeneration::from_value(1);
    observation.authorized = true;
    paths[ecmp::synthetic_path_id(seed)] = observation;
  }
};

int failures = 0;

void check(bool condition, const char* description) {
  if (!condition) {
    ++failures;
    std::printf("consumer check failed: %s\n", description);
  }
}

}  // namespace

int main() {
  using namespace ecmp;

  AuthorizedPaths view;
  for (std::uint64_t seed = 1000; seed < 1008; ++seed) {
    view.authorize(seed);
  }

  GovernorLimits limits;
  EcmpGovernor governor(limits, CoordinatorEpoch::from_value(1), &view);

  const SyntheticIds ids = synthetic_ids(1);
  const PublisherId publisher = synthetic_publisher_id(1);
  const WorkerBootId boot = synthetic_boot_id(1);
  PublisherRegistration registration;
  registration.publisher = publisher;
  registration.worker_boot = boot;
  registration.scope = AuthorityScope::for_fabric(ids.fabric);
  registration.capabilities = 3;
  registration.provenance = ids.provenance;
  ConditionList conditions(limits.max_explanation_entries);
  check(is_acceptance(governor.register_publisher(governor.epoch(), registration, conditions)),
        "publisher registration");

  CreateGroupRequest create;
  create.authority.epoch = governor.epoch();
  create.authority.publisher = publisher;
  create.authority.worker_boot = boot;
  create.authority.scope = registration.scope;
  create.authority.attempt = synthetic_attempt_id(1);
  create.group = synthetic_group_id(1);
  create.key = synthetic_group_key(ids);
  create.cost_semantics = synthetic_cost_semantics(ids, 1);
  create.hash_domain = ids.hash_domain;
  create.provenance = ids.provenance;
  create.bucket_count = *BucketCount::make(16);
  create.min_active_members = 1;
  create.members = synthetic_members(ids, 3, PathAuthorityGeneration::from_value(1));
  const MutationResult created = governor.create_group(create);
  check(is_acceptance(created.outcome), "group created");
  check(created.group.has_value() && created.group->lifecycle == GroupLifecycle::ACTIVE,
        "group is ACTIVE");

  const std::optional<GroupSnapshot> snapshot = governor.snapshot(create.group);
  check(snapshot.has_value(), "snapshot available");
  if (!snapshot.has_value()) {
    return 1;
  }
  const std::uint32_t share_a = snapshot->assignment.owned_bucket_count(synthetic_member_id(2000));
  const std::uint32_t share_b = snapshot->assignment.owned_bucket_count(synthetic_member_id(2001));
  const std::uint32_t share_c = snapshot->assignment.owned_bucket_count(synthetic_member_id(2002));
  std::printf("consumer: initial split %u/%u/%u over %u buckets\n", share_a, share_b, share_c,
              snapshot->bucket_count.value());
  check(share_a + share_b + share_c == snapshot->bucket_count.value(), "every bucket has an owner");
  const std::uint32_t maximum = std::max({share_a, share_b, share_c});
  const std::uint32_t minimum = std::min({share_a, share_b, share_c});
  check(maximum - minimum <= 1, "near-equal allocation");
  check(maximum == 6 && minimum == 5, "16 buckets over 3 equal members is 6/5/5");
  check(check_assignment(snapshot->assignment, snapshot->active_members) == AssignmentDefect::NONE,
        "assignment is structurally valid");

  RemoveMemberRequest remove;
  remove.authority.epoch = governor.epoch();
  remove.authority.publisher = publisher;
  remove.authority.worker_boot = boot;
  remove.authority.scope = registration.scope;
  remove.authority.attempt = synthetic_attempt_id(2);
  remove.group = create.group;
  remove.member = synthetic_member_id(2002);
  const MutationResult removed = governor.remove_member(remove);
  check(is_acceptance(removed.outcome), "member removed");
  check(removed.group.has_value() && removed.group->active_members == 2, "two active members");

  const std::optional<RebalanceRecord> record = governor.last_rebalance(create.group);
  check(record.has_value(), "rebalance recorded");
  if (record.has_value()) {
    // The minimum possible churn is what the removed member owned plus whatever
    // equalisation the survivors require: bucket_count - (kept by A + kept by B).
    const std::uint64_t target = snapshot->bucket_count.value() / 2;
    const std::uint64_t retained = std::min<std::uint64_t>(share_a, target) +
                                   std::min<std::uint64_t>(share_b, target);
    std::printf("consumer: churn=%llu retained=%llu\n",
                static_cast<unsigned long long>(record->churn),
                static_cast<unsigned long long>(retained));
    check(record->churn == snapshot->bucket_count.value() - retained,
          "deterministic minimum churn");
  }
  const std::optional<GroupSnapshot> after = governor.snapshot(create.group);
  check(after.has_value() && after->assignment.owned_bucket_count(synthetic_member_id(2000)) == 8,
        "member A owns 8 after rebalance");
  check(after.has_value() && after->assignment.owned_bucket_count(synthetic_member_id(2001)) == 8,
        "member B owns 8 after rebalance");
  std::vector<Condition> problems;
  check(governor.check_invariants(problems), "invariants hold");

  std::printf("consumer: version=%s groups=%llu churn=%llu\n",
              std::string(ecmp::kVersionString).c_str(),
              static_cast<unsigned long long>(governor.statistics().groups),
              record.has_value() ? static_cast<unsigned long long>(record->churn) : 0ull);
  if (failures != 0) {
    std::printf("consumer failed with %d problem(s)\n", failures);
    return 1;
  }
  std::printf("consumer completed successfully\n");
  return 0;
}
