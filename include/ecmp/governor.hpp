#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "ecmp/assignment.hpp"
#include "ecmp/authority.hpp"
#include "ecmp/group.hpp"
#include "ecmp/limits.hpp"
#include "ecmp/outcome.hpp"
#include "ecmp/upstream.hpp"

namespace ecmp {

namespace detail {
class GovernorState;
}  // namespace detail

// Structured result of one mutation attempt.
struct MutationResult {
  Outcome outcome = Outcome::INTERNAL_ERROR;
  ConditionList conditions;
  std::string detail;  // bounded operator hint, never the primary channel
  std::optional<GroupSummary> group;
  std::optional<RebalancePlanId> plan;  // set by REBALANCE_PLANNED

  [[nodiscard]] bool accepted() const noexcept { return is_acceptance(outcome); }
  [[nodiscard]] std::string render() const;

  friend bool operator==(const MutationResult&, const MutationResult&) = default;
};

struct CreateGroupRequest {
  AuthorityContext authority;
  ECMPGroupId group;
  GroupKey key;
  MembershipSource source = MembershipSource::DIRECT_PATH_SET;
  MultipathSetId multipath_set;
  MultipathSetGeneration multipath_generation;
  CostSemantics cost_semantics;
  HashDomainId hash_domain;
  BucketCount bucket_count;
  std::uint32_t min_active_members = 1;
  std::vector<MemberSpec> members;
  ProvenanceId provenance;
};

struct AddMemberRequest {
  AuthorityContext authority;
  ECMPGroupId group;
  MemberSpec member;
};

struct RemoveMemberRequest {
  AuthorityContext authority;
  ECMPGroupId group;
  ECMPMemberId member;
};

struct SetMemberEnabledRequest {
  AuthorityContext authority;
  ECMPGroupId group;
  ECMPMemberId member;
  bool enabled = false;
};

// Atomic membership-set change.  The result depends only on the current state and
// the requested set, never on the arrival order of the individual changes.
struct MembershipSetRequest {
  AuthorityContext authority;
  ECMPGroupId group;
  std::vector<MemberSpec> members;
};

struct MemberRevalidation {
  ECMPMemberId member;
  PathAuthorityGeneration path_authority;
  std::optional<CostClaim> cost;
};

struct RevalidateGroupRequest {
  AuthorityContext authority;
  ECMPGroupId group;
  std::vector<MemberRevalidation> members;
  std::optional<MultipathSetGeneration> multipath_generation;
};

struct RebalancePlanRequest {
  AuthorityContext authority;
  ECMPGroupId group;
  std::vector<MemberSpec> target_members;
};

struct RebalanceCommitRequest {
  AuthorityContext authority;
  ECMPGroupId group;
  RebalancePlanId plan;
};

struct RebalanceAbortRequest {
  AuthorityContext authority;
  ECMPGroupId group;
  RebalancePlanId plan;
};

struct GroupAdminRequest {
  AuthorityContext authority;
  ECMPGroupId group;
  ECMPGroupId successor;  // supersession only
};

// Authoritative upstream notifications.  These are not caller mutations: they
// report a change in a domain ECMP Governor does not own.
struct PathAuthorityChangeNotice {
  CoordinatorEpoch epoch;
  PublisherId publisher;
  WorkerBootId worker_boot;
  PathId path;
  PathAuthorityGeneration generation;
};

struct MultipathSetChangeNotice {
  CoordinatorEpoch epoch;
  PublisherId publisher;
  WorkerBootId worker_boot;
  MultipathSetId set;
  MultipathSetGeneration generation;
};

struct CostGenerationChangeNotice {
  CoordinatorEpoch epoch;
  PublisherId publisher;
  WorkerBootId worker_boot;
  CostClassId cost_class;
  CostPolicyGeneration generation;
};

struct GovernorStatistics {
  std::uint64_t groups = 0;
  std::uint64_t total_members = 0;
  std::uint64_t active_members = 0;
  std::uint64_t buckets = 0;
  std::uint64_t live_publishers = 0;
  std::uint64_t committed_rebalances = 0;
  std::uint64_t remembered_attempts = 0;
};

struct SaveReport {
  bool ok = false;
  Outcome outcome = Outcome::STORE_ERROR;
  std::string detail;
  std::uint64_t bytes = 0;
};

struct LoadReport {
  bool ok = false;
  Outcome outcome = Outcome::STORE_ERROR;
  std::string detail;
  std::uint32_t groups_loaded = 0;
  CoordinatorEpoch stored_epoch;
};

// ECMP Governor: the deterministic equal-cost multipath membership, eligibility
// and rebalance-governance runtime.
//
// Thread safety: all public methods are safe to call concurrently from any
// thread.  Queries run concurrently with each other; every mutation is applied
// atomically under one governor lock, so conflicting mutations on one group
// resolve in a single deterministic order and no partially applied rebalance is
// ever observable.  No method returns a mutable reference to internal state.
//
// Determinism: given the same starting state and the same sequence of accepted
// requests, every observable result (bucket map, generations, digests,
// explanations, diffs) is identical.  Nothing in this class consults a clock, a
// random source, a thread id, an address, or an unordered container iteration
// order.
class EcmpGovernor {
 public:
  explicit EcmpGovernor(GovernorLimits limits = GovernorLimits{},
                        CoordinatorEpoch epoch = CoordinatorEpoch::from_value(1),
                        const IPathAuthorityView* path_authority = nullptr,
                        const IMultipathSetView* multipath = nullptr);
  ~EcmpGovernor();
  EcmpGovernor(const EcmpGovernor&) = delete;
  EcmpGovernor& operator=(const EcmpGovernor&) = delete;
  EcmpGovernor(EcmpGovernor&&) = delete;
  EcmpGovernor& operator=(EcmpGovernor&&) = delete;

  // --- authority domain -----------------------------------------------------
  [[nodiscard]] CoordinatorEpoch epoch() const;
  [[nodiscard]] bool set_epoch(CoordinatorEpoch epoch, ConditionList& conditions);
  [[nodiscard]] const GovernorLimits& limits() const;

  [[nodiscard]] Outcome register_publisher(CoordinatorEpoch epoch,
                                           const PublisherRegistration& registration,
                                           ConditionList& conditions);
  [[nodiscard]] Outcome fence_publisher(const PublisherId& publisher,
                                        const WorkerBootId& worker_boot,
                                        ConditionList& conditions);
  [[nodiscard]] bool is_publisher_live(const PublisherId& publisher,
                                       const WorkerBootId& worker_boot) const;
  // Server-side authoritative registration of a publisher.  A client cannot widen
  // its own scope: the coordinator stamps the scope it actually granted.
  [[nodiscard]] std::optional<PublisherRegistration> registration(
      const PublisherId& publisher) const;
  [[nodiscard]] std::uint32_t live_publisher_count() const;

  // --- group mutations ------------------------------------------------------
  [[nodiscard]] MutationResult create_group(const CreateGroupRequest& request);
  [[nodiscard]] MutationResult add_member(const AddMemberRequest& request);
  [[nodiscard]] MutationResult remove_member(const RemoveMemberRequest& request);
  [[nodiscard]] MutationResult set_member_enabled(const SetMemberEnabledRequest& request);
  [[nodiscard]] MutationResult apply_membership_set(const MembershipSetRequest& request);
  [[nodiscard]] MutationResult revalidate_group(const RevalidateGroupRequest& request);
  [[nodiscard]] MutationResult plan_rebalance(const RebalancePlanRequest& request);
  [[nodiscard]] MutationResult commit_rebalance(const RebalanceCommitRequest& request);
  [[nodiscard]] MutationResult abort_rebalance(const RebalanceAbortRequest& request);
  [[nodiscard]] MutationResult withdraw_group(const GroupAdminRequest& request);
  [[nodiscard]] MutationResult revoke_group(const GroupAdminRequest& request);
  [[nodiscard]] MutationResult retire_group(const GroupAdminRequest& request);
  [[nodiscard]] MutationResult supersede_group(const GroupAdminRequest& request);

  // --- upstream notifications ----------------------------------------------
  [[nodiscard]] MutationResult notify_path_authority_change(const PathAuthorityChangeNotice& notice);
  [[nodiscard]] MutationResult notify_multipath_set_change(const MultipathSetChangeNotice& notice);
  [[nodiscard]] MutationResult notify_cost_generation_change(
      const CostGenerationChangeNotice& notice);

  // --- queries --------------------------------------------------------------
  [[nodiscard]] std::optional<GroupSnapshot> snapshot(const ECMPGroupId& group) const;
  [[nodiscard]] std::vector<GroupSummary> list_groups() const;
  [[nodiscard]] std::vector<GroupSummary> groups_for_path(const PathId& path) const;
  [[nodiscard]] std::vector<GroupSummary> groups_for_multipath_set(const MultipathSetId& set) const;
  [[nodiscard]] std::optional<RebalanceRecord> last_rebalance(const ECMPGroupId& group) const;
  [[nodiscard]] std::vector<HistoryEntry> history(const ECMPGroupId& group) const;
  [[nodiscard]] GovernorStatistics statistics() const;

  [[nodiscard]] Explanation explain_group(const ECMPGroupId& group) const;
  [[nodiscard]] Explanation explain_member(const ECMPGroupId& group,
                                           const ECMPMemberId& member) const;
  [[nodiscard]] Explanation explain_bucket(const ECMPGroupId& group, BucketId bucket) const;
  [[nodiscard]] Explanation explain_last_rebalance(const ECMPGroupId& group) const;
  [[nodiscard]] Explanation explain_authority(const ECMPGroupId& group) const;

  // Structural self check.  Used by the CLI, by the property tests and after
  // recovery.  Returns true when no problem was found.
  [[nodiscard]] bool check_invariants(std::vector<Condition>& problems) const;

  // --- persistence ----------------------------------------------------------
  [[nodiscard]] SaveReport save(const std::filesystem::path& path) const;
  [[nodiscard]] LoadReport load(const std::filesystem::path& path);

 private:
  std::unique_ptr<detail::GovernorState> state_;
};

// Deterministic derivation of a group identity from its semantic key and a
// lineage nonce.  Provided so that reproducible deployments can name groups
// without inventing random identities; the coordinator still enforces uniqueness.
[[nodiscard]] ECMPGroupId derive_group_id(const GroupKey& key, std::uint64_t lineage_nonce);

}  // namespace ecmp
