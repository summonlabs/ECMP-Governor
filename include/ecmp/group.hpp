#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "ecmp/assignment.hpp"
#include "ecmp/cost.hpp"
#include "ecmp/digest.hpp"
#include "ecmp/identity.hpp"
#include "ecmp/lifecycle.hpp"
#include "ecmp/outcome.hpp"

namespace ecmp {

// Semantic uniqueness of an ECMP group.  Generation, process incarnation and any
// mutable display label are deliberately absent: those change, identity does not.
struct GroupKey {
  FabricId fabric;
  RoutingNamespaceId routing_namespace;
  DestinationId destination;
  CostClassId cost_class;

  [[nodiscard]] bool is_well_formed() const noexcept {
    return !fabric.is_nil() && !routing_namespace.is_nil() && !destination.is_nil() &&
           !cost_class.is_nil();
  }

  friend auto operator<=>(const GroupKey&, const GroupKey&) noexcept = default;
  friend bool operator==(const GroupKey&, const GroupKey&) = default;
};

// One declared ECMP membership.  Identity is the ECMPMemberId, never a vector
// position; the position in a snapshot is derived from the canonical order.
struct MemberRecord {
  ECMPMemberId member;
  PathId path;
  PathAuthorityGeneration path_authority;
  MemberGeneration member_generation;
  CostClaim cost;
  ProvenanceId provenance;
  bool administratively_enabled = true;
  bool declared = true;
  MemberState state = MemberState::ACTIVE;

  [[nodiscard]] bool is_active() const noexcept { return state == MemberState::ACTIVE; }
};

// Caller supplied membership declaration.
struct MemberSpec {
  ECMPMemberId member;
  PathId path;
  PathAuthorityGeneration path_authority;
  MemberGeneration member_generation;
  CostClaim cost;
  ProvenanceId provenance;
  bool administratively_enabled = true;

  [[nodiscard]] bool is_well_formed() const noexcept {
    return !member.is_nil() && !path.is_nil() && cost.is_well_formed() && !provenance.is_nil();
  }
};

// Immutable snapshot of the complete authoritative state of one group.
struct GroupSnapshot {
  ECMPGroupId id;
  GroupKey key;
  MembershipSource source = MembershipSource::DIRECT_PATH_SET;
  GroupLifecycle lifecycle = GroupLifecycle::DECLARED;
  Currentness currentness;
  MembershipGeneration membership_generation;
  AssignmentGeneration assignment_generation;
  AuthorityGeneration authority_generation;
  CostSemantics cost_semantics;
  PathCost canonical_cost;
  HashDomainId hash_domain;
  BucketCount bucket_count;
  std::uint32_t min_active_members = 1;
  std::vector<MemberRecord> members;         // canonical order: (path, member id)
  std::vector<ECMPMemberId> active_members;  // canonical order, state == ACTIVE
  BucketAssignment assignment;
  MultipathSetId multipath_set;
  MultipathSetGeneration multipath_generation;
  CoordinatorEpoch epoch;
  PublisherId authority_publisher;
  ProvenanceId provenance;
  Digest membership_digest;
  Digest assignment_digest;
  Digest semantic_digest;
  std::optional<RebalancePlanId> pending_plan;

  [[nodiscard]] std::uint32_t active_member_count() const noexcept {
    return static_cast<std::uint32_t>(active_members.size());
  }
  [[nodiscard]] std::uint32_t declared_member_count() const noexcept;
  [[nodiscard]] const MemberRecord* find_member(const ECMPMemberId& member) const noexcept;
};

// Compact projection used by listings and mutation results.
struct GroupSummary {
  ECMPGroupId id;
  GroupKey key;
  MembershipSource source = MembershipSource::DIRECT_PATH_SET;
  GroupLifecycle lifecycle = GroupLifecycle::DECLARED;
  Currentness currentness;
  MembershipGeneration membership_generation;
  AssignmentGeneration assignment_generation;
  AuthorityGeneration authority_generation;
  std::uint32_t declared_members = 0;
  std::uint32_t active_members = 0;
  std::uint32_t min_active_members = 1;
  BucketCount bucket_count;
  Digest membership_digest;
  Digest assignment_digest;
  Digest semantic_digest;
};

[[nodiscard]] GroupSummary summarize(const GroupSnapshot& snapshot);

// One recorded change.  Bounded per group by GovernorLimits::max_history.
struct HistoryEntry {
  MembershipGeneration membership_generation;
  AssignmentGeneration assignment_generation;
  AuthorityGeneration authority_generation;
  ChangeReason reason = ChangeReason::CREATE;
  PublisherId publisher;
  CoordinatorEpoch epoch;
  std::uint64_t churn = 0;
  std::uint64_t moves_recorded = 0;
  std::optional<RebalancePlanId> plan;
  Digest membership_digest;
  Digest assignment_digest;
};

// The last committed rebalance of a group; carries the full move list so that
// "which buckets moved and why" is answerable exactly.
struct RebalanceRecord {
  RebalancePlanId plan;
  ChangeReason reason = ChangeReason::REVALIDATION;
  MembershipGeneration from_membership;
  MembershipGeneration to_membership;
  AssignmentGeneration from_assignment;
  AssignmentGeneration to_assignment;
  std::vector<BucketMove> moves;
  std::uint64_t churn = 0;
  Digest assignment_digest;
};

struct MemberChange {
  ECMPMemberId member;
  PathId path;
  MemberState before = MemberState::ACTIVE;
  MemberState after = MemberState::ACTIVE;
  bool added = false;
  bool removed = false;
  std::optional<PathAuthorityGeneration> path_authority_before;
  std::optional<PathAuthorityGeneration> path_authority_after;
  std::optional<CostClaim> cost_before;
  std::optional<CostClaim> cost_after;
  bool eligibility_changed = false;
  bool cost_changed = false;
};

// Deterministic structural diff between two snapshots of the same group.
struct GroupDiff {
  ECMPGroupId id;
  MembershipGeneration from_membership;
  MembershipGeneration to_membership;
  AssignmentGeneration from_assignment;
  AssignmentGeneration to_assignment;
  std::optional<GroupLifecycle> from_lifecycle;
  std::optional<GroupLifecycle> to_lifecycle;
  std::optional<Currentness> from_currentness;
  std::optional<Currentness> to_currentness;
  std::optional<AuthorityGeneration> from_authority;
  std::optional<AuthorityGeneration> to_authority;
  std::optional<CoordinatorEpoch> from_epoch;
  std::optional<CoordinatorEpoch> to_epoch;
  std::optional<MultipathSetGeneration> from_multipath;
  std::optional<MultipathSetGeneration> to_multipath;
  std::vector<MemberChange> members;  // canonical order
  std::vector<BucketMove> moves;      // ascending bucket order
  std::uint64_t churn = 0;
  Digest from_digest;
  Digest to_digest;

  [[nodiscard]] bool is_empty() const noexcept;
};

// Diff of two snapshots of the same group.  Ordering is canonical and the result
// depends only on the two inputs.
[[nodiscard]] GroupDiff diff_snapshots(const GroupSnapshot& before, const GroupSnapshot& after);

}  // namespace ecmp
