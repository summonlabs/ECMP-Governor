#include "ecmp/group.hpp"

#include <algorithm>
#include <map>
#include <string>
#include <tuple>
#include <vector>

namespace ecmp {
namespace {

struct MemberUnion {
  PathId path;
  ECMPMemberId member;
  const MemberRecord* before = nullptr;
  const MemberRecord* after = nullptr;
};

}  // namespace

const MemberRecord* GroupSnapshot::find_member(const ECMPMemberId& member) const noexcept {
  for (const MemberRecord& record : members) {
    if (record.member == member) {
      return &record;
    }
  }
  return nullptr;
}

std::uint32_t GroupSnapshot::declared_member_count() const noexcept {
  std::uint32_t total = 0;
  for (const MemberRecord& record : members) {
    if (record.declared) {
      ++total;
    }
  }
  return total;
}

GroupSummary summarize(const GroupSnapshot& snapshot) {
  GroupSummary summary;
  summary.id = snapshot.id;
  summary.key = snapshot.key;
  summary.source = snapshot.source;
  summary.lifecycle = snapshot.lifecycle;
  summary.currentness = snapshot.currentness;
  summary.membership_generation = snapshot.membership_generation;
  summary.assignment_generation = snapshot.assignment_generation;
  summary.authority_generation = snapshot.authority_generation;
  summary.declared_members = snapshot.declared_member_count();
  summary.active_members = snapshot.active_member_count();
  summary.min_active_members = snapshot.min_active_members;
  summary.bucket_count = snapshot.bucket_count;
  summary.membership_digest = snapshot.membership_digest;
  summary.assignment_digest = snapshot.assignment_digest;
  summary.semantic_digest = snapshot.semantic_digest;
  return summary;
}

bool GroupDiff::is_empty() const noexcept {
  return members.empty() && moves.empty() && !from_lifecycle.has_value() &&
         !to_lifecycle.has_value() && !from_currentness.has_value() && !to_currentness.has_value() &&
         !from_authority.has_value() && !to_authority.has_value() && !from_epoch.has_value() &&
         !to_epoch.has_value() && !from_multipath.has_value() && !to_multipath.has_value() &&
         from_membership == to_membership && from_assignment == to_assignment;
}

GroupDiff diff_snapshots(const GroupSnapshot& before, const GroupSnapshot& after) {
  GroupDiff diff;
  diff.id = after.id;
  diff.from_membership = before.membership_generation;
  diff.to_membership = after.membership_generation;
  diff.from_assignment = before.assignment_generation;
  diff.to_assignment = after.assignment_generation;
  if (before.lifecycle != after.lifecycle) {
    diff.from_lifecycle = before.lifecycle;
    diff.to_lifecycle = after.lifecycle;
  }
  if (!(before.currentness == after.currentness)) {
    diff.from_currentness = before.currentness;
    diff.to_currentness = after.currentness;
  }
  if (before.authority_generation != after.authority_generation) {
    diff.from_authority = before.authority_generation;
    diff.to_authority = after.authority_generation;
  }
  if (before.epoch != after.epoch) {
    diff.from_epoch = before.epoch;
    diff.to_epoch = after.epoch;
  }
  if (before.multipath_generation != after.multipath_generation) {
    diff.from_multipath = before.multipath_generation;
    diff.to_multipath = after.multipath_generation;
  }

  std::map<ECMPMemberId, MemberUnion> unions;
  for (const MemberRecord& record : before.members) {
    MemberUnion& entry = unions[record.member];
    entry.path = record.path;
    entry.member = record.member;
    entry.before = &record;
  }
  for (const MemberRecord& record : after.members) {
    MemberUnion& entry = unions[record.member];
    entry.path = record.path;
    entry.member = record.member;
    entry.after = &record;
  }

  std::vector<MemberUnion> ordered;
  ordered.reserve(unions.size());
  for (const auto& pair : unions) {
    ordered.push_back(pair.second);
  }
  std::sort(ordered.begin(), ordered.end(), [](const MemberUnion& left, const MemberUnion& right) {
    return std::tie(left.path, left.member) < std::tie(right.path, right.member);
  });

  for (const MemberUnion& entry : ordered) {
    const bool was_declared = entry.before != nullptr && entry.before->declared;
    const bool is_declared = entry.after != nullptr && entry.after->declared;
    const bool changed_state = (entry.before == nullptr) != (entry.after == nullptr) ||
                               (entry.before != nullptr && entry.after != nullptr &&
                                entry.before->state != entry.after->state);
    if (!changed_state && was_declared == is_declared) {
      continue;
    }
    MemberChange change;
    change.member = entry.member;
    change.path = entry.path;
    change.added = !was_declared && is_declared;
    change.removed = was_declared && !is_declared;
    if (entry.before != nullptr) {
      change.before = entry.before->state;
      change.path_authority_before = entry.before->path_authority;
      change.cost_before = entry.before->cost;
    }
    if (entry.after != nullptr) {
      change.after = entry.after->state;
      change.path_authority_after = entry.after->path_authority;
      change.cost_after = entry.after->cost;
    }
    change.eligibility_changed = entry.before != nullptr && entry.after != nullptr &&
                                 entry.before->state != entry.after->state;
    change.cost_changed = entry.before != nullptr && entry.after != nullptr &&
                          !(entry.before->cost == entry.after->cost);
    diff.members.push_back(std::move(change));
  }

  const std::size_t before_buckets = before.assignment.owners.size();
  const std::size_t after_buckets = after.assignment.owners.size();
  const std::size_t common = std::min(before_buckets, after_buckets);
  for (std::size_t bucket = 0; bucket < common; ++bucket) {
    const ECMPMemberId from = before.assignment.owners[bucket];
    const ECMPMemberId to = after.assignment.owners[bucket];
    if (from == to) {
      continue;
    }
    BucketMove move;
    move.bucket = BucketId::from_value(static_cast<std::uint32_t>(bucket));
    move.from = from;
    move.to = to;
    if (from.is_nil()) {
      move.reason = MoveReason::INITIAL_ASSIGNMENT;
    } else if (std::find(after.active_members.begin(), after.active_members.end(), from) ==
               after.active_members.end()) {
      move.reason = MoveReason::OWNER_REMOVED;
    } else {
      move.reason = MoveReason::OWNER_OVER_QUOTA;
    }
    diff.moves.push_back(move);
  }
  diff.churn = diff.moves.size();
  diff.from_digest = before.semantic_digest;
  diff.to_digest = after.semantic_digest;
  return diff;
}

}  // namespace ecmp
