#pragma once

#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <shared_mutex>
#include <string>
#include <vector>

#include "ecmp/governor.hpp"
#include "ecmp/persistence.hpp"

namespace ecmp::detail {

// One declared member plus the currentness of every upstream fact it depends on.
struct MemberEntry {
  MemberRecord record;
  bool path_authority_current = true;   // last observation matched the binding
  bool path_authority_authorized = false;
  bool multipath_current = true;
  bool cost_current = true;

  [[nodiscard]] bool upstream_current() const noexcept {
    return path_authority_current && multipath_current && cost_current;
  }
};

// A prepared but not yet committed rebalance.  The commit is bound to the exact
// generations the plan was computed from, which is what makes a stale completion
// impossible to apply.
struct PlanEntry {
  RebalancePlanId plan;
  MembershipGeneration from_membership;
  AssignmentGeneration from_assignment;
  AuthorityGeneration from_authority;
  MembershipGeneration target_membership;
  Digest target_membership_digest;
  std::vector<MemberSpec> target_members;
  std::vector<BucketMove> moves;
  BucketAssignment assignment;
  Digest assignment_digest;
  CoordinatorEpoch epoch;
  PublisherId publisher;
};

struct AttemptEntry {
  Digest payload;
  Outcome outcome = Outcome::INTERNAL_ERROR;
  ECMPGroupId group;
  ConditionCode primary = ConditionCode::NONE;
  std::string detail;
};

struct GroupState {
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
  std::vector<MemberEntry> members;  // canonical order: (path, member id)
  BucketAssignment assignment;
  MultipathSetId multipath_set;
  MultipathSetGeneration multipath_generation;
  PublisherId authority_publisher;
  WorkerBootId authority_boot;
  CoordinatorEpoch bound_epoch;
  ProvenanceId provenance;
  ECMPGroupId successor;
  ECMPGroupId predecessor;
  std::optional<PlanEntry> plan;
  std::deque<HistoryEntry> history;
  std::optional<RebalanceRecord> last_rebalance;

  // Reverse index bookkeeping so that index maintenance is exact and does not
  // depend on scanning every group.
  std::vector<PathId> indexed_paths;
  PublisherId indexed_authority;
  Digest declared_digest;  // digest of the declared member identity set

  [[nodiscard]] std::vector<ECMPMemberId> active_members() const;
  [[nodiscard]] std::uint32_t declared_count() const;
  [[nodiscard]] MemberEntry* find_member(const ECMPMemberId& member);
  [[nodiscard]] const MemberEntry* find_member(const ECMPMemberId& member) const;
};

struct PublisherEntry {
  PublisherRegistration registration;
  CoordinatorEpoch epoch;
};

class GovernorState {
 public:
  GovernorState(GovernorLimits limits, CoordinatorEpoch epoch,
                const IPathAuthorityView* path_authority, const IMultipathSetView* multipath);

  GovernorLimits limits;
  CoordinatorEpoch epoch;
  const IPathAuthorityView* path_authority = nullptr;
  const IMultipathSetView* multipath = nullptr;

  std::map<ECMPGroupId, GroupState> groups;
  std::map<GroupKey, ECMPGroupId> key_index;
  std::map<PathId, std::set<ECMPGroupId>> path_index;
  std::map<MultipathSetId, std::set<ECMPGroupId>> multipath_index;
  std::map<CostClassId, std::set<ECMPGroupId>> cost_class_index;
  std::map<PublisherId, std::set<ECMPGroupId>> authority_index;
  std::map<PublisherId, PublisherEntry> publishers;
  std::set<WorkerBootId> fenced_boots;
  std::map<MutationAttemptId, AttemptEntry> attempts;
  std::deque<MutationAttemptId> attempt_order;
  // Cost policy generation currently reported by the cost authority, per cost
  // class.  Live upstream knowledge, never persisted.
  std::map<CostClassId, CostPolicyGeneration> current_cost_policy;

  std::uint64_t total_members = 0;
  std::uint64_t committed_rebalances = 0;

  mutable std::shared_mutex mutex;

  [[nodiscard]] GroupState* find_group(const ECMPGroupId& id);
  [[nodiscard]] const GroupState* find_group(const ECMPGroupId& id) const;

  void index_paths(const GroupState& group);
  void unindex_paths(const GroupState& group);
  void index_group_paths(GroupState& group);
  void index_cost_class(GroupState& group);

  void remember_attempt(const MutationAttemptId& attempt, const AttemptEntry& entry);
  [[nodiscard]] const AttemptEntry* find_attempt(const MutationAttemptId& attempt) const;
  void clear_publishers_and_fences();
};

// Computes the authoritative structures that follow from the current member
// flags and assignment, then applies them and advances generations exactly where
// the semantics changed.
struct RefreshContext {
  ChangeReason reason = ChangeReason::REVALIDATION;
  GroupEvent event = GroupEvent::REVALIDATE;
  PublisherId publisher;
  WorkerBootId worker_boot;
  CoordinatorEpoch epoch;
  bool record_history = true;
  // True for publisher mutations: the group's authority binding follows the
  // caller and the authority generation advances when that binding changes.
  bool bind_authority = true;
  // False during recovery: the durable bucket map survives as desired state and
  // is not recomputed from the (not yet revalidated) member flags.
  bool recompute_assignment = true;
};

[[nodiscard]] std::optional<Outcome> refresh_group(GovernorState& state, GroupState& group,
                                                   const RefreshContext& context,
                                                   ConditionList& conditions);

[[nodiscard]] Digest compute_membership_digest(const GroupState& group);
[[nodiscard]] Digest compute_semantic_digest(const GroupState& group);
[[nodiscard]] Digest compute_declared_digest(const GroupState& group);

// Immutable value snapshot of one group.
[[nodiscard]] GroupSnapshot make_snapshot(const GroupState& group);

[[nodiscard]] MemberRecord make_record(const MemberSpec& spec, bool administratively_enabled);

// Persistence codec for the whole governor payload.  Decoding is strict: every
// structurally impossible record is rejected with a distinct store defect.
[[nodiscard]] std::vector<std::uint8_t> encode_governor_payload(const GovernorState& state);
[[nodiscard]] StoreDefect decode_governor_payload(std::span<const std::uint8_t> bytes,
                                                  const GovernorLimits& limits,
                                                  std::map<ECMPGroupId, GroupState>& groups,
                                                  std::uint64_t& committed_rebalances,
                                                  std::string& detail);

}  // namespace ecmp::detail
