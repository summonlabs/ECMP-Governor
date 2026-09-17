// ECMP Governor 1.0.0 benchmark.
//
// Every number printed here is a machine and build observation: completed
// operations per second as measured on this host, this compiler and this build
// type.  Nothing here is a product claim about any other machine.

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "ecmp/ecmp.hpp"

namespace {

using namespace ecmp;

class AuthorizedPaths final : public IPathAuthorityView {
 public:
  [[nodiscard]] std::optional<PathAuthorityObservation> observe(
      const PathId&) const override {
    PathAuthorityObservation observation;
    observation.generation = PathAuthorityGeneration::from_value(1);
    observation.authorized = true;
    return observation;
  }
};

double milliseconds_since(const std::chrono::steady_clock::time_point& start) {
  const auto elapsed = std::chrono::steady_clock::now() - start;
  return std::chrono::duration<double, std::milli>(elapsed).count();
}

void report(const char* operation, std::uint64_t completed, double milliseconds) {
  const double seconds = milliseconds / 1000.0;
  const double rate = seconds > 0.0 ? static_cast<double>(completed) / seconds : 0.0;
  std::printf("%-34s completed=%-8llu elapsed_ms=%-10.2f per_second=%.0f\n", operation,
              static_cast<unsigned long long>(completed), milliseconds, rate);
}

}  // namespace

int main() {
  AuthorizedPaths view;
  GovernorLimits limits;
  limits.max_groups = 200000;
  limits.max_total_members = 4000000;
  limits.max_history = 4;
  limits.max_persistence_record_bytes = 96u << 20;

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
  if (!is_acceptance(governor.register_publisher(governor.epoch(), registration, conditions))) {
    std::printf("registration failed\n");
    return 1;
  }

  constexpr std::uint32_t kGroups = 10000;
  constexpr std::uint32_t kMembers = 4;
  constexpr std::uint32_t kBuckets = 64;

  const auto create_start = std::chrono::steady_clock::now();
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
    request.members = synthetic_members(ids, kMembers, PathAuthorityGeneration::from_value(1));
    if (!is_acceptance(governor.create_group(request).outcome)) {
      std::printf("group creation failed at index %u\n", index);
      return 1;
    }
  }
  report("group_create", kGroups, milliseconds_since(create_start));

  const auto add_start = std::chrono::steady_clock::now();
  for (std::uint32_t index = 0; index < kGroups; ++index) {
    const SyntheticIds ids = synthetic_ids(index + 1);
    AddMemberRequest request;
    request.authority.epoch = governor.epoch();
    request.authority.publisher = publisher;
    request.authority.worker_boot = boot;
    request.authority.scope = registration.scope;
    request.authority.attempt = synthetic_attempt_id(2000000 + index);
    request.group = synthetic_group_id(index + 1);
    request.member = synthetic_member_spec(ids, 2004, 1004, PathAuthorityGeneration::from_value(1));
    (void)governor.add_member(request);
  }
  report("member_add_with_rebalance", kGroups, milliseconds_since(add_start));

  const auto remove_start = std::chrono::steady_clock::now();
  for (std::uint32_t index = 0; index < kGroups; ++index) {
    RemoveMemberRequest request;
    request.authority.epoch = governor.epoch();
    request.authority.publisher = publisher;
    request.authority.worker_boot = boot;
    request.authority.scope = registration.scope;
    request.authority.attempt = synthetic_attempt_id(3000000 + index);
    request.group = synthetic_group_id(index + 1);
    request.member = synthetic_member_id(2004);
    (void)governor.remove_member(request);
  }
  report("member_remove_with_rebalance", kGroups, milliseconds_since(remove_start));

  const auto snapshot_start = std::chrono::steady_clock::now();
  std::uint64_t digest_bytes = 0;
  for (std::uint32_t index = 0; index < kGroups; ++index) {
    const std::optional<GroupSnapshot> snapshot = governor.snapshot(synthetic_group_id(index + 1));
    if (snapshot.has_value()) {
      digest_bytes += snapshot->semantic_digest.bytes().size();
    }
  }
  report("snapshot_with_digest", kGroups, milliseconds_since(snapshot_start));
  std::printf("%-34s bytes=%llu\n", "semantic_digest_bytes",
              static_cast<unsigned long long>(digest_bytes));

  const auto list_start = std::chrono::steady_clock::now();
  const std::vector<GroupSummary> groups = governor.list_groups();
  report("list_groups", groups.size(), milliseconds_since(list_start));

  // Targeted invalidation of one path shared by every group.
  PathAuthorityChangeNotice notice;
  notice.epoch = governor.epoch();
  notice.publisher = publisher;
  notice.worker_boot = boot;
  notice.path = synthetic_path_id(1000);
  notice.generation = PathAuthorityGeneration::from_value(1);
  const auto invalidation_start = std::chrono::steady_clock::now();
  const MutationResult invalidation = governor.notify_path_authority_change(notice);
  report("targeted_path_invalidation", groups.size(), milliseconds_since(invalidation_start));
  std::printf("%-34s outcome=%s\n", "targeted_path_invalidation_result",
              std::string(to_string(invalidation.outcome)).c_str());

  const std::filesystem::path store =
      std::filesystem::temp_directory_path() / "ecmp-governor-bench" / "population.store";
  std::error_code error;
  std::filesystem::create_directories(store.parent_path(), error);
  const auto save_start = std::chrono::steady_clock::now();
  const SaveReport saved = governor.save(store);
  report("persistence_save", groups.size(), milliseconds_since(save_start));
  std::printf("%-34s ok=%d bytes=%llu detail=%s\n", "persistence_save_result", saved.ok ? 1 : 0,
              static_cast<unsigned long long>(saved.bytes), saved.detail.c_str());

  EcmpGovernor recovered(limits, CoordinatorEpoch::from_value(1), &view);
  const auto load_start = std::chrono::steady_clock::now();
  const LoadReport loaded = recovered.load(store);
  report("persistence_load_and_recover", loaded.groups_loaded, milliseconds_since(load_start));
  std::printf("%-34s ok=%d\n", "persistence_load_result", loaded.ok ? 1 : 0);

  std::vector<Condition> problems;
  const auto check_start = std::chrono::steady_clock::now();
  bool clean = governor.check_invariants(problems);
  report("invariant_check", groups.size(), milliseconds_since(check_start));
  std::printf("%-34s clean=%d problems=%zu\n", "invariant_check_result", clean ? 1 : 0,
              problems.size());

  // Synthetic scale: one hundred thousand groups.  This is deliberately a separate
  // population with a smaller bucket count so the exercise stays practical on a
  // workstation while still covering the configured scale target.
  {
    constexpr std::uint32_t kLargeGroups = 100000;
    constexpr std::uint32_t kLargeBuckets = 16;
    EcmpGovernor large(limits, CoordinatorEpoch::from_value(1), &view);
    if (!is_acceptance(large.register_publisher(large.epoch(), registration, conditions))) {
      std::printf("large registration failed\n");
      return 1;
    }
    const auto large_start = std::chrono::steady_clock::now();
    for (std::uint32_t index = 0; index < kLargeGroups; ++index) {
      const SyntheticIds ids = synthetic_ids(index + 1);
      CreateGroupRequest request;
      request.authority.epoch = large.epoch();
      request.authority.publisher = publisher;
      request.authority.worker_boot = boot;
      request.authority.scope = registration.scope;
      request.authority.attempt = synthetic_attempt_id(4000000 + index);
      request.group = synthetic_group_id(index + 1);
      request.key = synthetic_group_key(ids);
      request.key.fabric = registration.scope.fabric;
      request.cost_semantics = synthetic_cost_semantics(ids, 1);
      request.hash_domain = ids.hash_domain;
      request.provenance = ids.provenance;
      request.bucket_count = *BucketCount::make(kLargeBuckets);
      request.min_active_members = 1;
      request.members = synthetic_members(ids, 2, PathAuthorityGeneration::from_value(1));
      if (!is_acceptance(large.create_group(request).outcome)) {
        std::printf("large group creation failed at index %u\n", index);
        return 1;
      }
    }
    report("group_create_100k", kLargeGroups, milliseconds_since(large_start));
    std::vector<Condition> large_problems;
    const auto large_check = std::chrono::steady_clock::now();
    const bool large_clean = large.check_invariants(large_problems);
    report("invariant_check_100k", kLargeGroups, milliseconds_since(large_check));
    std::printf("%-34s clean=%d problems=%zu groups=%llu\n", "invariant_check_100k_result",
                large_clean ? 1 : 0, large_problems.size(),
                static_cast<unsigned long long>(large.statistics().groups));
    const auto large_invalidate = std::chrono::steady_clock::now();
    const MutationResult large_notice = large.notify_path_authority_change(notice);
    report("targeted_invalidation_100k", kLargeGroups, milliseconds_since(large_invalidate));
    std::printf("%-34s outcome=%s\n", "targeted_invalidation_100k_result",
                std::string(to_string(large_notice.outcome)).c_str());
    if (!large_clean) {
      clean = false;
    }
  }

  std::filesystem::remove_all(store.parent_path(), error);
  return clean ? 0 : 1;
}
