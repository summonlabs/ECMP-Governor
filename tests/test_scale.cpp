#include <cstdint>
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

}  // namespace

ECMP_TEST(test_scale_groups_members_buckets_and_shared_paths) {
  constexpr std::uint32_t kGroups = 1000;
  constexpr std::uint32_t kMembers = 8;
  constexpr std::uint32_t kBuckets = 64;

  AlwaysAuthorized view;
  GovernorLimits limits;
  limits.max_groups = 200000;
  limits.max_total_members = 2000000;
  limits.max_history = 8;
  limits.max_persistence_record_bytes = 8u << 20;
  EcmpGovernor governor(limits, CoordinatorEpoch::from_value(1), &view);

  const PublisherId publisher = synthetic_publisher_id(1);
  const WorkerBootId boot = synthetic_boot_id(1);
  PublisherRegistration registration;
  registration.publisher = publisher;
  registration.worker_boot = boot;
  registration.scope = AuthorityScope::for_fabric(synthetic_ids(1).fabric);
  registration.capabilities = 3;
  registration.provenance = synthetic_ids(1).provenance;
  ConditionList conditions(limits.max_explanation_entries);
  ECMP_REQUIRE(governor.register_publisher(governor.epoch(), registration, conditions) ==
               Outcome::REGISTERED);

  // Every group shares the same paths: one path invalidation must reach exactly the
  // groups that depend on it, and nothing else.
  for (std::uint32_t index = 0; index < kGroups; ++index) {
    const SyntheticIds ids = synthetic_ids(index + 1);
    CreateGroupRequest request;
    request.authority.epoch = governor.epoch();
    request.authority.publisher = publisher;
    request.authority.worker_boot = boot;
    request.authority.scope = registration.scope;
    request.authority.attempt = synthetic_attempt_id(1000000 + index);
    request.group = synthetic_group_id(index + 1);
    request.key = synthetic_group_key(ids);
    request.key.fabric = registration.scope.fabric;
    request.cost_semantics = synthetic_cost_semantics(ids, 1);
    request.hash_domain = ids.hash_domain;
    request.provenance = ids.provenance;
    request.bucket_count = *BucketCount::make(kBuckets);
    request.min_active_members = 2;
    const std::uint32_t member_count = 2 + (index % (kMembers - 1));
    request.members = synthetic_members(ids, member_count, PathAuthorityGeneration::from_value(1));
    const MutationResult result = governor.create_group(request);
    ECMP_REQUIRE(is_acceptance(result.outcome));
  }

  const GovernorStatistics statistics = governor.statistics();
  ECMP_CHECK_EQ(statistics.groups, std::uint64_t{kGroups});
  ECMP_CHECK(statistics.total_members >= kGroups * 2);
  std::vector<Condition> problems;
  ECMP_CHECK(governor.check_invariants(problems));

  // Targeted invalidation through the reverse index: exactly one path.
  const PathId shared_path = synthetic_path_id(1000);
  const std::vector<GroupSummary> dependents = governor.groups_for_path(shared_path);
  ECMP_CHECK_EQ(dependents.size(), std::size_t{kGroups});

  PathAuthorityChangeNotice notice;
  notice.epoch = governor.epoch();
  notice.publisher = publisher;
  notice.worker_boot = boot;
  notice.path = shared_path;
  notice.generation = PathAuthorityGeneration::from_value(1);
  // The observation is unchanged, so nothing is invalidated.
  ECMP_CHECK(governor.notify_path_authority_change(notice).outcome == Outcome::NO_CHANGE);
  ECMP_CHECK(governor.check_invariants(problems));

  // Mass revalidation of every group through the bulk membership path.
  for (std::uint32_t index = 0; index < kGroups; ++index) {
    const SyntheticIds ids = synthetic_ids(index + 1);
    RevalidateGroupRequest request;
    request.authority.epoch = governor.epoch();
    request.authority.publisher = publisher;
    request.authority.worker_boot = boot;
    request.authority.scope = registration.scope;
    request.authority.attempt = synthetic_attempt_id(2000000 + index);
    request.group = synthetic_group_id(index + 1);
    const MutationResult result = governor.revalidate_group(request);
    ECMP_CHECK(is_acceptance(result.outcome));
  }
  ECMP_CHECK(governor.check_invariants(problems));

  // Persistence of the whole population, then a conservative recovery of it.
  const std::filesystem::path store =
      std::filesystem::temp_directory_path() / "ecmp-governor-scale" / "scale.store";
  std::error_code error;
  std::filesystem::create_directories(store.parent_path(), error);
  const SaveReport saved = governor.save(store);
  ECMP_REQUIRE(saved.ok);

  EcmpGovernor recovered(limits, CoordinatorEpoch::from_value(1), &view);
  const LoadReport loaded = recovered.load(store);
  ECMP_REQUIRE(loaded.ok);
  ECMP_CHECK_EQ(loaded.groups_loaded, kGroups);
  ECMP_CHECK(recovered.check_invariants(problems));
  std::filesystem::remove(store, error);
}
