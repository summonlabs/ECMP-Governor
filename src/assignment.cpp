#include "ecmp/assignment.hpp"

#include <algorithm>
#include <cstdint>
#include <vector>

#include "ecmp/bytes.hpp"

namespace ecmp {
namespace {

constexpr std::string_view kAssignmentDigestDomain = "ecmp.assignment.v1";

[[nodiscard]] std::uint32_t find_member(std::span<const ECMPMemberId> members,
                                        const ECMPMemberId& member) noexcept {
  for (std::uint32_t index = 0; index < members.size(); ++index) {
    if (members[index] == member) {
      return index;
    }
  }
  return static_cast<std::uint32_t>(members.size());
}

}  // namespace

std::string_view to_string(MoveReason reason) noexcept {
  switch (reason) {
    case MoveReason::INITIAL_ASSIGNMENT: return "INITIAL_ASSIGNMENT";
    case MoveReason::OWNER_REMOVED: return "OWNER_REMOVED";
    case MoveReason::OWNER_OVER_QUOTA: return "OWNER_OVER_QUOTA";
  }
  return "UNKNOWN_MOVE_REASON";
}

std::string_view to_string(AssignmentDefect defect) noexcept {
  switch (defect) {
    case AssignmentDefect::NONE: return "NONE";
    case AssignmentDefect::COUNT_MISMATCH: return "COUNT_MISMATCH";
    case AssignmentDefect::DUPLICATE_MEMBER_INPUT: return "DUPLICATE_MEMBER_INPUT";
    case AssignmentDefect::UNKNOWN_OWNER: return "UNKNOWN_OWNER";
    case AssignmentDefect::UNASSIGNED_BUCKET: return "UNASSIGNED_BUCKET";
    case AssignmentDefect::UNBALANCED: return "UNBALANCED";
  }
  return "UNKNOWN_ASSIGNMENT_DEFECT";
}

std::uint32_t BucketAssignment::owned_bucket_count(const ECMPMemberId& member) const noexcept {
  std::uint32_t total = 0;
  for (const ECMPMemberId& owner : owners) {
    if (owner == member) {
      ++total;
    }
  }
  return total;
}

Digest BucketAssignment::digest() const {
  Encoder encoder;
  encoder.u32(count.value());
  encoder.u32(static_cast<std::uint32_t>(owners.size()));
  for (const ECMPMemberId& owner : owners) {
    encoder.raw(owner.bytes());
  }
  return domain_digest(kAssignmentDigestDomain, encoder.bytes());
}

std::vector<std::uint32_t> balanced_bucket_counts(std::uint32_t bucket_count,
                                                 std::uint32_t member_count) {
  std::vector<std::uint32_t> counts;
  if (member_count == 0) {
    return counts;
  }
  counts.resize(member_count, 0);
  const std::uint32_t base = bucket_count / member_count;
  const std::uint32_t extra = bucket_count % member_count;
  for (std::uint32_t index = 0; index < member_count; ++index) {
    counts[index] = base + (index < extra ? 1u : 0u);
  }
  return counts;
}

RebalanceComputation compute_rebalance(const BucketAssignment& previous,
                                      std::span<const ECMPMemberId> canonical_members,
                                      BucketCount count) {
  RebalanceComputation result;
  const std::uint32_t bucket_count = count.value();
  const std::uint32_t member_count = static_cast<std::uint32_t>(canonical_members.size());

  result.assignment.count = count;
  result.assignment.owners.assign(bucket_count, ECMPMemberId{});

  const std::vector<std::uint32_t> target = balanced_bucket_counts(bucket_count, member_count);
  std::vector<std::uint32_t> kept(member_count, 0);
  std::vector<MoveReason> release_reason(bucket_count, MoveReason::INITIAL_ASSIGNMENT);

  // Retention phase.  Every member keeps as many of its own lowest numbered
  // buckets as its target share allows; that retention is exactly
  // min(previous_share, target_share), hence the total number of moved buckets is
  // the minimum possible.
  for (std::uint32_t bucket = 0; bucket < bucket_count; ++bucket) {
    if (bucket >= previous.owners.size()) {
      break;
    }
    const ECMPMemberId previous_owner = previous.owners[bucket];
    if (previous_owner.is_nil()) {
      continue;
    }
    const std::uint32_t index = find_member(canonical_members, previous_owner);
    if (index == member_count) {
      release_reason[bucket] = MoveReason::OWNER_REMOVED;
      continue;
    }
    if (kept[index] < target[index]) {
      result.assignment.owners[bucket] = previous_owner;
      ++kept[index];
    } else {
      release_reason[bucket] = MoveReason::OWNER_OVER_QUOTA;
    }
  }

  // Fill phase.  Free buckets are handed out in ascending bucket order to
  // members in canonical order until every deficit is satisfied.  This is the
  // lexicographically smallest minimum-churn completion.
  std::uint32_t cursor = 0;
  for (std::uint32_t index = 0; index < member_count; ++index) {
    std::uint32_t deficit = target[index] - kept[index];
    while (deficit > 0) {
      while (cursor < bucket_count && !result.assignment.owners[cursor].is_nil()) {
        ++cursor;
      }
      result.assignment.owners[cursor] = canonical_members[index];
      --deficit;
      ++cursor;
    }
  }

  // Move list.  A move exists exactly when the owner changed, including the
  // previously unowned -> owned transition of an initial assignment.
  result.moves.reserve(bucket_count);
  for (std::uint32_t bucket = 0; bucket < bucket_count; ++bucket) {
    const ECMPMemberId previous_owner =
        bucket < previous.owners.size() ? previous.owners[bucket] : ECMPMemberId{};
    const ECMPMemberId owner = result.assignment.owners[bucket];
    if (previous_owner == owner) {
      if (!owner.is_nil()) {
        ++result.retained_buckets;
      }
      continue;
    }
    BucketMove move;
    move.bucket = BucketId::from_value(bucket);
    move.from = previous_owner;
    move.to = owner;
    if (previous_owner.is_nil()) {
      move.reason = MoveReason::INITIAL_ASSIGNMENT;
    } else {
      move.reason = release_reason[bucket];
    }
    result.moves.push_back(move);
  }
  return result;
}

RebalanceComputation compute_initial_assignment(std::span<const ECMPMemberId> canonical_members,
                                               BucketCount count) {
  BucketAssignment empty;
  empty.count = count;
  empty.owners.assign(count.value(), ECMPMemberId{});
  return compute_rebalance(empty, canonical_members, count);
}

std::uint64_t minimum_possible_churn(const BucketAssignment& previous,
                                    std::span<const ECMPMemberId> canonical_members) {
  const std::uint32_t bucket_count = previous.count.value();
  const std::uint32_t member_count = static_cast<std::uint32_t>(canonical_members.size());
  const std::vector<std::uint32_t> target = balanced_bucket_counts(bucket_count, member_count);

  std::uint64_t retained = 0;
  for (std::uint32_t index = 0; index < member_count; ++index) {
    const std::uint32_t share = previous.owned_bucket_count(canonical_members[index]);
    retained += std::min<std::uint64_t>(share, target[index]);
  }
  return static_cast<std::uint64_t>(bucket_count) - retained;
}

AssignmentDefect check_assignment(const BucketAssignment& assignment,
                                 std::span<const ECMPMemberId> active_members) {
  if (!assignment.is_sized()) {
    return AssignmentDefect::COUNT_MISMATCH;
  }
  for (std::size_t left = 0; left < active_members.size(); ++left) {
    for (std::size_t right = left + 1; right < active_members.size(); ++right) {
      if (active_members[left] == active_members[right]) {
        return AssignmentDefect::DUPLICATE_MEMBER_INPUT;
      }
    }
  }
  for (const ECMPMemberId& owner : assignment.owners) {
    if (owner.is_nil()) {
      if (!active_members.empty()) {
        return AssignmentDefect::UNASSIGNED_BUCKET;
      }
      continue;
    }
    if (find_member(active_members, owner) == active_members.size()) {
      return AssignmentDefect::UNKNOWN_OWNER;
    }
  }
  if (active_members.empty()) {
    return AssignmentDefect::NONE;
  }
  std::uint32_t minimum = assignment.count.value();
  std::uint32_t maximum = 0;
  for (const ECMPMemberId& member : active_members) {
    const std::uint32_t share = assignment.owned_bucket_count(member);
    minimum = std::min(minimum, share);
    maximum = std::max(maximum, share);
  }
  if (maximum - minimum > 1) {
    return AssignmentDefect::UNBALANCED;
  }
  return AssignmentDefect::NONE;
}

}  // namespace ecmp
