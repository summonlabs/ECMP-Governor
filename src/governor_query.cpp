#include <algorithm>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "ecmp/bytes.hpp"
#include "ecmp/digest.hpp"
#include "governor_state.hpp"

namespace ecmp {

using detail::GroupState;
using detail::GovernorState;

EcmpGovernor::EcmpGovernor(GovernorLimits limits, CoordinatorEpoch epoch,
                           const IPathAuthorityView* path_authority,
                           const IMultipathSetView* multipath)
    : state_(std::make_unique<GovernorState>(limits, epoch, path_authority, multipath)) {
  std::string reason;
  if (!limits.is_coherent(reason)) {
    // Running with contradictory or dead limits is never acceptable: the
    // governor refuses to exist instead of silently disabling a bound.
    throw std::invalid_argument("ECMP Governor limits are incoherent: " + reason);
  }
}

EcmpGovernor::~EcmpGovernor() = default;

std::string MutationResult::render() const {
  std::string out(to_string(outcome));
  if (group.has_value()) {
    out += " group=";
    out += group->id.to_text();
    out += " lifecycle=";
    out += to_string(group->lifecycle);
    out += " membership=" + std::to_string(group->membership_generation.value());
    out += " assignment=" + std::to_string(group->assignment_generation.value());
    out += " authority=" + std::to_string(group->authority_generation.value());
    out += " active=" + std::to_string(group->active_members);
    out += " declared=" + std::to_string(group->declared_members);
  }
  if (plan.has_value()) {
    out += " plan=";
    out += plan->to_text();
  }
  out += '\n';
  for (const Condition& condition : conditions.entries()) {
    out += "  ";
    out += condition.render();
    out += '\n';
  }
  if (!detail.empty()) {
    out += "detail: ";
    out += detail;
    out += '\n';
  }
  return out;
}

CoordinatorEpoch EcmpGovernor::epoch() const {
  std::shared_lock lock(state_->mutex);
  return state_->epoch;
}

const GovernorLimits& EcmpGovernor::limits() const { return state_->limits; }

bool EcmpGovernor::set_epoch(CoordinatorEpoch epoch, ConditionList& conditions) {
  std::unique_lock lock(state_->mutex);
  GovernorState& state = *state_;
  if (epoch <= state.epoch) {
    conditions.add(make_condition(ConditionCode::AUTHORITY_EPOCH_STALE, "epoch", epoch.value(),
                                  state.epoch.value()));
    return false;
  }
  state.epoch = epoch;
  state.clear_publishers_and_fences();
  for (auto& entry : state.groups) {
    GroupState& group = entry.second;
    if (is_administratively_closed(group.lifecycle)) {
      continue;
    }
    if (!group.bound_epoch.is_zero() && group.bound_epoch == epoch) {
      continue;
    }
    const auto next = group.authority_generation.next();
    if (next.has_value()) {
      group.authority_generation = *next;
    }
    group.currentness.add(CurrentnessCause::STALE_EPOCH);
    group.currentness.add(CurrentnessCause::REVALIDATION_REQUIRED);
    group.plan.reset();
    // Every upstream proof is unproven in the new epoch, but the durable desired
    // assignment survives: an epoch advance changes authority, not the intended
    // bucket map.
    for (detail::MemberEntry& member : group.members) {
      member.path_authority_current = false;
      member.path_authority_authorized = false;
      member.multipath_current = false;
      member.cost_current = false;
    }
    detail::RefreshContext context;
    context.reason = ChangeReason::EPOCH_INVALIDATION;
    context.event = GroupEvent::INVALIDATE_EPOCH;
    context.publisher = group.authority_publisher;
    context.worker_boot = group.authority_boot;
    context.epoch = state.epoch;
    context.bind_authority = false;
    context.recompute_assignment = false;
    ConditionList ignored(state.limits.max_explanation_entries);
    (void)detail::refresh_group(state, group, context, ignored);
  }
  return true;
}

Outcome EcmpGovernor::register_publisher(CoordinatorEpoch epoch,
                                         const PublisherRegistration& registration,
                                         ConditionList& conditions) {
  std::unique_lock lock(state_->mutex);
  GovernorState& state = *state_;
  if (!registration.is_well_formed()) {
    conditions.add(make_condition(ConditionCode::MALFORMED_IDENTITY, "publisher_registration"));
    return Outcome::MALFORMED_REQUEST;
  }
  if (!(epoch == state.epoch)) {
    conditions.add(make_condition(ConditionCode::AUTHORITY_EPOCH_STALE, "epoch", epoch.value(),
                                  state.epoch.value()));
    return Outcome::STALE_EPOCH;
  }
  if (registration.scope.kind == ScopeKind::DENY_ALL) {
    conditions.add(make_condition(ConditionCode::SCOPE_DENIED, "DENY_ALL"));
    return Outcome::UNAUTHORIZED;
  }
  if (registration.capabilities == 0) {
    conditions.add(make_condition(ConditionCode::CAPABILITY_MISSING, "capabilities", 0, 1));
    return Outcome::UNAUTHORIZED;
  }
  if (state.fenced_boots.count(registration.worker_boot) != 0) {
    conditions.add(make_condition(ConditionCode::WORKER_FENCED, "worker_boot"));
    return Outcome::STALE_WORKER;
  }
  const auto existing = state.publishers.find(registration.publisher);
  if (existing != state.publishers.end()) {
    if (!(existing->second.registration.worker_boot == registration.worker_boot)) {
      // The previous incarnation of this publisher is fenced by the act of
      // accepting a fresh boot for the same publisher identity.
      if (state.fenced_boots.size() >= state.limits.max_publishers) {
        conditions.add(make_condition(ConditionCode::PUBLISHER_LIMIT, "fenced_boots",
                                      state.fenced_boots.size(), state.limits.max_publishers));
        return Outcome::RESOURCE_LIMIT;
      }
      state.fenced_boots.insert(existing->second.registration.worker_boot);
    }
  } else if (state.publishers.size() >= state.limits.max_publishers) {
    conditions.add(make_condition(ConditionCode::PUBLISHER_LIMIT, "publishers",
                                  state.publishers.size(), state.limits.max_publishers));
    return Outcome::RESOURCE_LIMIT;
  }
  detail::PublisherEntry entry;
  entry.registration = registration;
  entry.epoch = epoch;
  state.publishers[registration.publisher] = entry;
  return Outcome::REGISTERED;
}

Outcome EcmpGovernor::fence_publisher(const PublisherId& publisher, const WorkerBootId& worker_boot,
                                      ConditionList& conditions) {
  std::unique_lock lock(state_->mutex);
  GovernorState& state = *state_;
  if (publisher.is_nil() || worker_boot.is_nil()) {
    conditions.add(make_condition(ConditionCode::MALFORMED_IDENTITY, "publisher"));
    return Outcome::MALFORMED_REQUEST;
  }
  const auto it = state.publishers.find(publisher);
  if (it == state.publishers.end() || !(it->second.registration.worker_boot == worker_boot)) {
    conditions.add(make_condition(ConditionCode::WORKER_FENCED, "worker_boot"));
    return Outcome::FENCED;
  }
  state.publishers.erase(it);
  if (state.fenced_boots.size() < state.limits.max_publishers) {
    state.fenced_boots.insert(worker_boot);
  }
  const auto owned = state.authority_index.find(publisher);
  if (owned != state.authority_index.end()) {
    const std::set<ECMPGroupId> dependents = owned->second;
    for (const ECMPGroupId& id : dependents) {
      const auto group_it = state.groups.find(id);
      if (group_it == state.groups.end()) {
        continue;
      }
      GroupState& group = group_it->second;
      if (!(group.authority_boot == worker_boot)) {
        continue;
      }
      if (is_administratively_closed(group.lifecycle)) {
        continue;
      }
      group.currentness.add(CurrentnessCause::FENCED_PUBLISHER);
      group.currentness.add(CurrentnessCause::REVALIDATION_REQUIRED);
      group.plan.reset();
      for (detail::MemberEntry& member : group.members) {
        member.path_authority_current = false;
        member.path_authority_authorized = false;
        member.multipath_current = false;
        member.cost_current = false;
      }
      detail::RefreshContext context;
      context.reason = ChangeReason::EPOCH_INVALIDATION;
      context.event = GroupEvent::INVALIDATE_EPOCH;
      context.publisher = publisher;
      context.worker_boot = worker_boot;
      context.epoch = state.epoch;
      context.bind_authority = false;
      context.recompute_assignment = false;
      ConditionList ignored(state.limits.max_explanation_entries);
      (void)detail::refresh_group(state, group, context, ignored);
    }
  }
  return Outcome::FENCED;
}

bool EcmpGovernor::is_publisher_live(const PublisherId& publisher,
                                     const WorkerBootId& worker_boot) const {
  std::shared_lock lock(state_->mutex);
  const auto it = state_->publishers.find(publisher);
  if (it == state_->publishers.end()) {
    return false;
  }
  return it->second.registration.worker_boot == worker_boot &&
         state_->fenced_boots.count(worker_boot) == 0;
}

std::optional<PublisherRegistration> EcmpGovernor::registration(
    const PublisherId& publisher) const {
  std::shared_lock lock(state_->mutex);
  const auto it = state_->publishers.find(publisher);
  if (it == state_->publishers.end()) {
    return std::nullopt;
  }
  return it->second.registration;
}

std::uint32_t EcmpGovernor::live_publisher_count() const {
  std::shared_lock lock(state_->mutex);
  return static_cast<std::uint32_t>(state_->publishers.size());
}

std::optional<GroupSnapshot> EcmpGovernor::snapshot(const ECMPGroupId& group_id) const {
  std::shared_lock lock(state_->mutex);
  const GroupState* group = state_->find_group(group_id);
  if (group == nullptr) {
    return std::nullopt;
  }
  return detail::make_snapshot(*group);
}

std::vector<GroupSummary> EcmpGovernor::list_groups() const {
  std::shared_lock lock(state_->mutex);
  std::vector<GroupSummary> out;
  out.reserve(state_->groups.size());
  for (const auto& entry : state_->groups) {
    out.push_back(summarize(detail::make_snapshot(entry.second)));
  }
  return out;
}

std::vector<GroupSummary> EcmpGovernor::groups_for_path(const PathId& path) const {
  std::shared_lock lock(state_->mutex);
  std::vector<GroupSummary> out;
  const auto it = state_->path_index.find(path);
  if (it == state_->path_index.end()) {
    return out;
  }
  for (const ECMPGroupId& id : it->second) {
    const GroupState* group = state_->find_group(id);
    if (group != nullptr) {
      out.push_back(summarize(detail::make_snapshot(*group)));
    }
  }
  return out;
}

std::vector<GroupSummary> EcmpGovernor::groups_for_multipath_set(const MultipathSetId& set) const {
  std::shared_lock lock(state_->mutex);
  std::vector<GroupSummary> out;
  const auto it = state_->multipath_index.find(set);
  if (it == state_->multipath_index.end()) {
    return out;
  }
  for (const ECMPGroupId& id : it->second) {
    const GroupState* group = state_->find_group(id);
    if (group != nullptr) {
      out.push_back(summarize(detail::make_snapshot(*group)));
    }
  }
  return out;
}

std::optional<RebalanceRecord> EcmpGovernor::last_rebalance(const ECMPGroupId& group_id) const {
  std::shared_lock lock(state_->mutex);
  const GroupState* group = state_->find_group(group_id);
  if (group == nullptr || !group->last_rebalance.has_value()) {
    return std::nullopt;
  }
  return group->last_rebalance;
}

std::vector<HistoryEntry> EcmpGovernor::history(const ECMPGroupId& group_id) const {
  std::shared_lock lock(state_->mutex);
  const GroupState* group = state_->find_group(group_id);
  if (group == nullptr) {
    return {};
  }
  return std::vector<HistoryEntry>(group->history.begin(), group->history.end());
}

GovernorStatistics EcmpGovernor::statistics() const {
  std::shared_lock lock(state_->mutex);
  GovernorStatistics statistics;
  statistics.groups = state_->groups.size();
  statistics.total_members = state_->total_members;
  statistics.buckets = 0;
  for (const auto& entry : state_->groups) {
    for (const detail::MemberEntry& member : entry.second.members) {
      if (member.record.is_active()) {
        ++statistics.active_members;
      }
    }
    statistics.buckets += entry.second.bucket_count.value();
  }
  statistics.live_publishers = state_->publishers.size();
  statistics.committed_rebalances = state_->committed_rebalances;
  statistics.remembered_attempts = state_->attempts.size();
  return statistics;
}

Explanation EcmpGovernor::explain_group(const ECMPGroupId& group_id) const {
  std::shared_lock lock(state_->mutex);
  const GroupState* group = state_->find_group(group_id);
  Explanation explanation("group " + group_id.to_text(), state_->limits.max_explanation_entries);
  if (group == nullptr) {
    explanation.add(make_condition(ConditionCode::GROUP_UNKNOWN, group_id.to_text()));
    return explanation;
  }
  explanation.add(make_condition(
      ConditionCode::NONE, std::string("lifecycle=") + std::string(to_string(group->lifecycle)),
      static_cast<std::uint64_t>(group->lifecycle), group->min_active_members));
  explanation.add(make_condition(ConditionCode::NONE, "declared_members", group->declared_count(),
                                 group->min_active_members));
  explanation.add(make_condition(ConditionCode::NONE, "active_members",
                                 group->active_members().size(), group->min_active_members));
  explanation.add(make_condition(ConditionCode::NONE, "min_active_members",
                                 group->min_active_members, group->min_active_members));
  explanation.add(make_condition(ConditionCode::NONE, "membership_generation",
                                 group->membership_generation.value()));
  explanation.add(make_condition(ConditionCode::NONE, "assignment_generation",
                                 group->assignment_generation.value()));
  explanation.add(make_condition(ConditionCode::NONE, "authority_generation",
                                 group->authority_generation.value()));
  explanation.add(make_condition(ConditionCode::NONE, "bucket_count", group->bucket_count.value()));
  explanation.add(make_condition(ConditionCode::NONE, "min_active_members_met",
                                 group->active_members().size() >= group->min_active_members ? 1 : 0,
                                 group->min_active_members));
  if (group->currentness.is_current()) {
    explanation.add(make_condition(ConditionCode::NONE, "currentness=CURRENT"));
  } else {
    for (const CurrentnessCause cause : group->currentness.causes()) {
      explanation.add(make_condition(ConditionCode::REVALIDATION_REQUIRED,
                                     std::string(to_string(cause))));
    }
  }
  if (group->plan.has_value()) {
    explanation.add(make_condition(ConditionCode::PLAN_STALE, "pending_plan",
                                   group->plan->from_membership.value(),
                                   group->plan->from_assignment.value()));
  }
  if (!group->successor.is_nil()) {
    explanation.add(make_condition(ConditionCode::GROUP_TERMINAL, "successor"));
  }
  if (!group->predecessor.is_nil()) {
    explanation.add(make_condition(ConditionCode::GROUP_TERMINAL, "predecessor"));
  }
  return explanation;
}

Explanation EcmpGovernor::explain_member(const ECMPGroupId& group_id,
                                         const ECMPMemberId& member) const {
  std::shared_lock lock(state_->mutex);
  Explanation explanation("member " + member.to_text() + " in group " + group_id.to_text(),
                          state_->limits.max_explanation_entries);
  const GroupState* group = state_->find_group(group_id);
  if (group == nullptr) {
    explanation.add(make_condition(ConditionCode::GROUP_UNKNOWN, group_id.to_text()));
    return explanation;
  }
  const detail::MemberEntry* entry = group->find_member(member);
  if (entry == nullptr) {
    explanation.add(make_condition(ConditionCode::MEMBER_UNKNOWN, member.to_text()));
    return explanation;
  }
  const MemberRecord& record = entry->record;
  explanation.add(make_condition(ConditionCode::NONE,
                                 std::string("state=") + std::string(to_string(record.state)),
                                 static_cast<std::uint64_t>(record.state), 0));
  explanation.add(make_condition(ConditionCode::NONE, "declared", record.declared ? 1 : 0, 1));
  explanation.add(make_condition(ConditionCode::NONE, "administratively_enabled",
                                 record.administratively_enabled ? 1 : 0, 1));
  explanation.add(make_condition(ConditionCode::NONE, "path_authority_binding",
                                 record.path_authority.value()));
  explanation.add(make_condition(ConditionCode::NONE, "path_authority_current",
                                 entry->path_authority_current ? 1 : 0, 1));
  explanation.add(make_condition(ConditionCode::NONE, "path_authority_authorized",
                                 entry->path_authority_authorized ? 1 : 0, 1));
  explanation.add(make_condition(ConditionCode::NONE, "multipath_current",
                                 entry->multipath_current ? 1 : 0, 1));
  explanation.add(make_condition(ConditionCode::NONE, "cost_current",
                                 entry->cost_current ? 1 : 0, 1));
  explanation.add(make_condition(ConditionCode::NONE, "member_generation",
                                 record.member_generation.value()));
  explanation.add(make_condition(ConditionCode::NONE, "owned_buckets",
                                 group->assignment.owned_bucket_count(record.member)));
  if (!record.administratively_enabled) {
    explanation.add(make_condition(ConditionCode::MEMBER_DISABLED, member.to_text()));
  }
  if (!entry->path_authority_current) {
    explanation.add(make_condition(ConditionCode::PATH_AUTHORITY_STALE, record.path.to_text(),
                                   record.path_authority.value()));
  }
  if (!entry->multipath_current) {
    explanation.add(make_condition(ConditionCode::MULTIPATH_SET_STALE, record.path.to_text()));
  }
  if (!entry->cost_current) {
    explanation.add(make_condition(ConditionCode::COST_POLICY_STALE, record.path.to_text()));
  }
  return explanation;
}

Explanation EcmpGovernor::explain_bucket(const ECMPGroupId& group_id, BucketId bucket) const {
  std::shared_lock lock(state_->mutex);
  Explanation explanation(
      "bucket " + std::to_string(bucket.value()) + " in group " + group_id.to_text(),
      state_->limits.max_explanation_entries);
  const GroupState* group = state_->find_group(group_id);
  if (group == nullptr) {
    explanation.add(make_condition(ConditionCode::GROUP_UNKNOWN, group_id.to_text()));
    return explanation;
  }
  if (bucket.value() >= group->bucket_count.value()) {
    explanation.add(make_condition(ConditionCode::BUCKET_LIMIT, "bucket", bucket.value(),
                                   group->bucket_count.value()));
    return explanation;
  }
  const ECMPMemberId owner = group->assignment.owners[bucket.value()];
  if (owner.is_nil()) {
    explanation.add(make_condition(ConditionCode::ASSIGNMENT_UNASSIGNED_BUCKET, "bucket",
                                   bucket.value()));
    return explanation;
  }
  explanation.add(make_condition(ConditionCode::NONE, "owner", bucket.value()));
  if (group->last_rebalance.has_value()) {
    for (const BucketMove& move : group->last_rebalance->moves) {
      if (move.bucket == bucket) {
        explanation.add(make_condition(
            ConditionCode::NONE, std::string("last_move=") + std::string(to_string(move.reason)),
            move.from.is_nil() ? 0 : 1, 1));
        break;
      }
    }
  }
  return explanation;
}

Explanation EcmpGovernor::explain_last_rebalance(const ECMPGroupId& group_id) const {
  std::shared_lock lock(state_->mutex);
  Explanation explanation("last rebalance of group " + group_id.to_text(),
                          state_->limits.max_explanation_entries);
  const GroupState* group = state_->find_group(group_id);
  if (group == nullptr) {
    explanation.add(make_condition(ConditionCode::GROUP_UNKNOWN, group_id.to_text()));
    return explanation;
  }
  if (!group->last_rebalance.has_value()) {
    explanation.add(make_condition(ConditionCode::PLAN_MISSING, "last_rebalance"));
    return explanation;
  }
  const RebalanceRecord& record = *group->last_rebalance;
  explanation.add(make_condition(ConditionCode::NONE,
                                 std::string("reason=") + std::string(to_string(record.reason)),
                                 static_cast<std::uint64_t>(record.reason), 0));
  explanation.add(make_condition(ConditionCode::NONE, "churn", record.churn, record.churn));
  explanation.add(make_condition(ConditionCode::NONE, "from_membership",
                                 record.from_membership.value(), record.to_membership.value()));
  explanation.add(make_condition(ConditionCode::NONE, "from_assignment",
                                 record.from_assignment.value(), record.to_assignment.value()));
  for (const BucketMove& move : record.moves) {
    explanation.add(make_condition(ConditionCode::NONE,
                                   std::string("move:") + std::string(to_string(move.reason)),
                                   move.bucket.value(), 1));
  }
  return explanation;
}

Explanation EcmpGovernor::explain_authority(const ECMPGroupId& group_id) const {
  std::shared_lock lock(state_->mutex);
  Explanation explanation("authority of group " + group_id.to_text(),
                          state_->limits.max_explanation_entries);
  const GroupState* group = state_->find_group(group_id);
  if (group == nullptr) {
    explanation.add(make_condition(ConditionCode::GROUP_UNKNOWN, group_id.to_text()));
    return explanation;
  }
  explanation.add(make_condition(ConditionCode::NONE, "coordinator_epoch",
                                 state_->epoch.value(), group->bound_epoch.value()));
  explanation.add(make_condition(ConditionCode::NONE, "authority_publisher",
                                 group->authority_publisher.is_nil() ? 0 : 1, 1));
  explanation.add(make_condition(ConditionCode::NONE, "authority_generation",
                                 group->authority_generation.value()));
  explanation.add(make_condition(ConditionCode::NONE, "authority_current",
                                 group->currentness.authority_current() ? 1 : 0, 1));
  for (const CurrentnessCause cause : group->currentness.causes()) {
    explanation.add(make_condition(ConditionCode::REVALIDATION_REQUIRED,
                                   std::string(to_string(cause))));
  }
  const auto publisher = state_->publishers.find(group->authority_publisher);
  if (publisher == state_->publishers.end()) {
    explanation.add(make_condition(ConditionCode::PUBLISHER_UNKNOWN, "authority_publisher"));
  } else {
    explanation.add(make_condition(ConditionCode::NONE, publisher->second.registration.scope.render()));
  }
  return explanation;
}

ECMPGroupId derive_group_id(const GroupKey& key, std::uint64_t lineage_nonce) {
  Encoder encoder;
  encoder.raw(key.fabric.bytes());
  encoder.raw(key.routing_namespace.bytes());
  encoder.raw(key.destination.bytes());
  encoder.raw(key.cost_class.bytes());
  encoder.u64(lineage_nonce);
  const Digest digest = domain_digest("ecmp.group-id.v1", encoder.bytes());
  std::array<std::uint8_t, ECMPGroupId::kByteCount> raw{};
  std::copy(digest.bytes().begin(), digest.bytes().begin() + ECMPGroupId::kByteCount, raw.begin());
  return ECMPGroupId::from_bytes(raw);
}

bool EcmpGovernor::check_invariants(std::vector<Condition>& problems) const {
  std::shared_lock lock(state_->mutex);
  const GovernorState& state = *state_;
  std::uint64_t declared_total = 0;

  if (state.key_index.size() != state.groups.size()) {
    problems.push_back(make_condition(ConditionCode::INTERNAL_INVARIANT, "key_index_size",
                                      state.key_index.size(), state.groups.size()));
  }

  for (const auto& entry : state.groups) {
    const GroupState& group = entry.second;
    const std::string subject = group.id.to_text();
    if (!(entry.first == group.id)) {
      problems.push_back(make_condition(ConditionCode::INTERNAL_INVARIANT, "group_map_key"));
    }
    const auto key_it = state.key_index.find(group.key);
    if (key_it == state.key_index.end() || !(key_it->second == group.id)) {
      problems.push_back(make_condition(ConditionCode::INTERNAL_INVARIANT, "key_index"));
    }
    if (group.bucket_count.value() == 0 || group.bucket_count.value() > state.limits.max_buckets) {
      problems.push_back(make_condition(ConditionCode::INTERNAL_INVARIANT, "bucket_count",
                                        group.bucket_count.value(), state.limits.max_buckets));
    }
    if (!group.assignment.is_sized()) {
      problems.push_back(make_condition(ConditionCode::ASSIGNMENT_COUNT_MISMATCH, subject,
                                        group.assignment.owners.size(),
                                        group.bucket_count.value()));
    }
    if (group.currentness.bits() >= (1u << kCurrentnessCauseCount)) {
      problems.push_back(make_condition(ConditionCode::INTERNAL_INVARIANT, "currentness_bits",
                                        group.currentness.bits()));
    }
    if (group.min_active_members == 0 ||
        group.min_active_members > state.limits.max_members_per_group) {
      problems.push_back(make_condition(ConditionCode::INTERNAL_INVARIANT, "min_active_members",
                                        group.min_active_members));
    }

    std::uint32_t declared = 0;
    std::vector<ECMPMemberId> seen;
    seen.reserve(group.members.size());
    for (std::size_t index = 0; index < group.members.size(); ++index) {
      const detail::MemberEntry& member = group.members[index];
      if (member.record.declared) {
        ++declared;
      }
      if (member.record.member.is_nil()) {
        problems.push_back(make_condition(ConditionCode::MALFORMED_IDENTITY, subject));
      }
      if (std::find(seen.begin(), seen.end(), member.record.member) != seen.end()) {
        problems.push_back(make_condition(ConditionCode::MEMBER_DUPLICATE, subject));
      }
      seen.push_back(member.record.member);
      if (index > 0) {
        const detail::MemberEntry& previous = group.members[index - 1];
        if (std::make_pair(member.record.path, member.record.member) <
            std::make_pair(previous.record.path, previous.record.member)) {
          problems.push_back(make_condition(ConditionCode::INTERNAL_INVARIANT, "member_order", index));
        }
      }
      if (member.record.is_active() && !member.upstream_current()) {
        problems.push_back(make_condition(ConditionCode::PATH_AUTHORITY_STALE, subject));
      }
      if (member.record.is_active() && !member.record.declared) {
        problems.push_back(make_condition(ConditionCode::INTERNAL_INVARIANT, "active_undeclared"));
      }
      if (!member.record.cost.is_well_formed()) {
        problems.push_back(make_condition(ConditionCode::COST_CLASS_MISMATCH, subject));
      }
    }
    declared_total += declared;

    if (declared > state.limits.max_members_per_group) {
      problems.push_back(make_condition(ConditionCode::MEMBER_SET_LIMIT, subject, declared,
                                        state.limits.max_members_per_group));
    }
    if (declared > group.bucket_count.value()) {
      problems.push_back(make_condition(ConditionCode::BUCKET_LIMIT, subject, declared,
                                        group.bucket_count.value()));
    }
    if (declared > 0 && group.membership_generation.is_zero()) {
      problems.push_back(make_condition(ConditionCode::INTERNAL_INVARIANT, "membership_generation"));
    }

    const std::vector<ECMPMemberId> active = group.active_members();
    const bool assignment_authoritative = group.lifecycle == GroupLifecycle::ACTIVE ||
                                          group.lifecycle == GroupLifecycle::DEGRADED ||
                                          group.lifecycle == GroupLifecycle::REBALANCING;
    if (assignment_authoritative) {
      const AssignmentDefect defect = check_assignment(group.assignment, active);
      if (defect != AssignmentDefect::NONE) {
        problems.push_back(make_condition(
            defect == AssignmentDefect::UNBALANCED    ? ConditionCode::ASSIGNMENT_UNBALANCED
            : defect == AssignmentDefect::UNKNOWN_OWNER ? ConditionCode::ASSIGNMENT_UNKNOWN_OWNER
            : defect == AssignmentDefect::UNASSIGNED_BUCKET
                ? ConditionCode::ASSIGNMENT_UNASSIGNED_BUCKET
                : ConditionCode::ASSIGNMENT_COUNT_MISMATCH,
            subject, static_cast<std::uint64_t>(defect)));
      }
    }
    if (!is_administratively_closed(group.lifecycle) && group.lifecycle != GroupLifecycle::DECLARED) {
      LifecycleInputs inputs;
      inputs.declared_members = declared;
      inputs.active_members = static_cast<std::uint32_t>(active.size());
      inputs.min_active_members = group.min_active_members;
      inputs.plan_pending = group.plan.has_value();
      inputs.authority_current = group.currentness.authority_current();
      const GroupLifecycle derived = derive_lifecycle(inputs);
      if (!(derived == group.lifecycle) && !(derived == GroupLifecycle::DECLARED)) {
        problems.push_back(make_condition(ConditionCode::INTERNAL_INVARIANT, "lifecycle_derived",
                                          static_cast<std::uint64_t>(group.lifecycle),
                                          static_cast<std::uint64_t>(derived)));
      }
    }
    if (group.lifecycle == GroupLifecycle::DECLARED) {
      if (declared != 0 || !active.empty()) {
        problems.push_back(make_condition(ConditionCode::INTERNAL_INVARIANT, "declared_with_members",
                                          declared, active.size()));
      }
    }
    if (group.plan.has_value()) {
      if (!(group.plan->assignment.digest() == group.plan->assignment_digest)) {
        problems.push_back(make_condition(ConditionCode::INTERNAL_INVARIANT, "plan_assignment_digest"));
      }
    }
    if (!group.successor.is_nil()) {
      const GroupState* successor = state.find_group(group.successor);
      if (successor == nullptr) {
        problems.push_back(make_condition(ConditionCode::GROUP_UNKNOWN, "successor"));
      } else if (!(successor->predecessor == group.id)) {
        problems.push_back(make_condition(ConditionCode::INTERNAL_INVARIANT, "successor_lineage"));
      }
    }
    if (!group.predecessor.is_nil() && state.find_group(group.predecessor) == nullptr) {
      problems.push_back(make_condition(ConditionCode::GROUP_UNKNOWN, "predecessor"));
    }
  }

  if (declared_total != state.total_members) {
    problems.push_back(make_condition(ConditionCode::INTERNAL_INVARIANT, "total_members",
                                      state.total_members, declared_total));
  }

  // Reverse indexes must agree with the records, in both directions.
  std::map<PathId, std::set<ECMPGroupId>> expected_paths;
  std::map<MultipathSetId, std::set<ECMPGroupId>> expected_multipath;
  std::map<CostClassId, std::set<ECMPGroupId>> expected_costs;
  std::map<PublisherId, std::set<ECMPGroupId>> expected_authority;
  for (const auto& entry : state.groups) {
    const GroupState& group = entry.second;
    for (const detail::MemberEntry& member : group.members) {
      if (member.record.declared) {
        expected_paths[member.record.path].insert(group.id);
      }
    }
    if (!group.multipath_set.is_nil()) {
      expected_multipath[group.multipath_set].insert(group.id);
    }
    if (!group.key.cost_class.is_nil()) {
      expected_costs[group.key.cost_class].insert(group.id);
    }
    if (!group.authority_publisher.is_nil()) {
      expected_authority[group.authority_publisher].insert(group.id);
    }
  }
  if (!(expected_paths == state.path_index)) {
    problems.push_back(make_condition(ConditionCode::INTERNAL_INVARIANT, "path_index"));
  }
  if (!(expected_multipath == state.multipath_index)) {
    problems.push_back(make_condition(ConditionCode::INTERNAL_INVARIANT, "multipath_index"));
  }
  if (!(expected_costs == state.cost_class_index)) {
    problems.push_back(make_condition(ConditionCode::INTERNAL_INVARIANT, "cost_class_index"));
  }
  if (!(expected_authority == state.authority_index)) {
    problems.push_back(make_condition(ConditionCode::INTERNAL_INVARIANT, "authority_index"));
  }
  return problems.empty();
}

}  // namespace ecmp
