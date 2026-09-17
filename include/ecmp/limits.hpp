#pragma once

#include <cstdint>
#include <string>

namespace ecmp {

// Absolute hard ceiling for any bucket count, independent of configuration.
inline constexpr std::uint32_t kAbsoluteMaxBuckets = 1u << 20;

// Every field below is a live limit: each one is consulted on the path it
// bounds.  A zero value disables the capability it bounds (for example
// max_groups == 0 rejects every group creation) rather than acting as
// "unlimited".
struct GovernorLimits {
  std::uint32_t max_groups = 100000;
  std::uint32_t max_members_per_group = 64;
  std::uint32_t max_total_members = 1000000;
  std::uint32_t max_buckets = 1024;
  // Churn budget for a single batch membership change.  Single-member changes
  // and authoritative invalidations are never rejected by this budget.
  std::uint32_t max_rebalance_moves = 1024;
  std::uint32_t max_batch_size = 256;
  std::uint32_t max_history = 64;
  std::uint32_t max_frame_bytes = 262144;
  std::uint32_t max_sessions = 64;
  std::uint32_t max_publishers = 1024;
  std::uint32_t max_persistence_record_bytes = 1048576;
  std::uint32_t max_explanation_entries = 64;
  std::uint32_t max_attempts_remembered = 256;

  // Returns false and fills `reason` when the limit set is internally
  // incoherent, so that no impossible configuration can be configured.
  [[nodiscard]] bool is_coherent(std::string& reason) const;
};

}  // namespace ecmp
