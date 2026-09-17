#include "ecmp/limits.hpp"

#include <string>

namespace ecmp {
namespace {

bool fail(std::string& reason, const char* message) {
  reason = message;
  return false;
}

}  // namespace

bool GovernorLimits::is_coherent(std::string& reason) const {
  if (max_buckets == 0 || max_buckets > kAbsoluteMaxBuckets) {
    return fail(reason, "max_buckets must be in [1, kAbsoluteMaxBuckets]");
  }
  if (max_members_per_group == 0) {
    return fail(reason, "max_members_per_group must be at least 1");
  }
  if (max_members_per_group > max_buckets) {
    return fail(reason, "max_members_per_group must not exceed max_buckets");
  }
  if (max_total_members < max_members_per_group) {
    return fail(reason, "max_total_members must be at least max_members_per_group");
  }
  if (max_groups == 0) {
    return fail(reason, "max_groups must be at least 1");
  }
  if (max_rebalance_moves == 0 || max_rebalance_moves > max_buckets) {
    return fail(reason, "max_rebalance_moves must be in [1, max_buckets]");
  }
  if (max_batch_size == 0) {
    return fail(reason, "max_batch_size must be at least 1");
  }
  if (max_history == 0) {
    return fail(reason, "max_history must be at least 1");
  }
  if (max_attempts_remembered == 0) {
    return fail(reason, "max_attempts_remembered must be at least 1");
  }
  if (max_explanation_entries == 0) {
    return fail(reason, "max_explanation_entries must be at least 1");
  }
  if (max_frame_bytes < 4096 || max_frame_bytes > (64u << 20)) {
    return fail(reason, "max_frame_bytes must be in [4096, 64MiB]");
  }
  if (max_sessions == 0) {
    return fail(reason, "max_sessions must be at least 1");
  }
  if (max_publishers == 0) {
    return fail(reason, "max_publishers must be at least 1");
  }
  if (max_persistence_record_bytes < 4096) {
    return fail(reason, "max_persistence_record_bytes must be at least 4096");
  }
  reason.clear();
  return true;
}

}  // namespace ecmp
