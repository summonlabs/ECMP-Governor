#include "governor_state.hpp"

#include <algorithm>
#include <string>
#include <tuple>
#include <utility>

#include "ecmp/bytes.hpp"
#include "ecmp/digest.hpp"

namespace ecmp::detail {
namespace {

constexpr std::string_view kSemanticDigestDomain = "ecmp.semantic.v1";
constexpr std::string_view kMembershipDigestDomain = "ecmp.membership.v1";
constexpr std::string_view kDeclaredDigestDomain = "ecmp.declared.v1";
constexpr std::string_view kGroupIdDomain = "ecmp.group-id.v1";

[[nodiscard]] bool canonical_less(const MemberRecord& left, const MemberRecord& right) noexcept {
  return std::tie(left.path, left.member) < std::tie(right.path, right.member);
}

void sort_members(std::vector<MemberEntry>& members) {
  std::stable_sort(members.begin(), members.end(),
                   [](const MemberEntry& left, const MemberEntry& right) {
                     return canonical_less(left.record, right.record);
                   });
}

void encode_cost_binding(Encoder& encoder, const CostModelBinding& binding) {
  encoder.raw(binding.model.bytes());
  encoder.u32(binding.model_version);
  encoder.raw(binding.route_class.bytes());
  encoder.u64(binding.policy_generation.value());
}

void encode_cost_claim_full(Encoder& encoder, const CostClaim& claim) {
  encoder.raw(claim.cost_class.bytes());
  encode_cost_binding(encoder, claim.binding);
  encoder.i64(claim.cost.units);
  encoder.u32(claim.cost.scale);
  encoder.raw(claim.source.bytes());
}

void encode_member_record_full(Encoder& encoder, const MemberRecord& record) {
  encoder.raw(record.member.bytes());
  encoder.raw(record.path.bytes());
  encoder.u64(record.path_authority.value());
  encoder.u64(record.member_generation.value());
  encoder.u8(static_cast<std::uint8_t>(record.state));
  encoder.boolean(record.administratively_enabled);
  encoder.boolean(record.declared);
  encode_cost_claim_full(encoder, record.cost);
  encoder.raw(record.provenance.bytes());
}

void encode_group_identity(Encoder& encoder, const GroupState& group) {
  encoder.raw(group.id.bytes());
  encoder.raw(group.key.fabric.bytes());
  encoder.raw(group.key.routing_namespace.bytes());
  encoder.raw(group.key.destination.bytes());
  encoder.raw(group.key.cost_class.bytes());
}

}  // namespace

MemberRecord make_record(const MemberSpec& spec, bool administratively_enabled) {
  MemberRecord record;
  record.member = spec.member;
  record.path = spec.path;
  record.path_authority = spec.path_authority;
  record.member_generation = spec.member_generation;
  record.cost = spec.cost;
  record.provenance = spec.provenance;
  record.administratively_enabled = administratively_enabled;
  record.declared = true;
  record.state = MemberState::ACTIVE;
  return record;
}

std::vector<ECMPMemberId> GroupState::active_members() const {
  std::vector<ECMPMemberId> out;
  out.reserve(members.size());
  for (const MemberEntry& entry : members) {
    if (entry.record.is_active()) {
      out.push_back(entry.record.member);
    }
  }
  return out;
}

std::uint32_t GroupState::declared_count() const {
  std::uint32_t total = 0;
  for (const MemberEntry& entry : members) {
    if (entry.record.declared) {
      ++total;
    }
  }
  return total;
}

MemberEntry* GroupState::find_member(const ECMPMemberId& member) {
  for (MemberEntry& entry : members) {
    if (entry.record.member == member) {
      return &entry;
    }
  }
  return nullptr;
}

const MemberEntry* GroupState::find_member(const ECMPMemberId& member) const {
  for (const MemberEntry& entry : members) {
    if (entry.record.member == member) {
      return &entry;
    }
  }
  return nullptr;
}

GovernorState::GovernorState(GovernorLimits limits_in, CoordinatorEpoch epoch_in,
                             const IPathAuthorityView* path_authority_in,
                             const IMultipathSetView* multipath_in)
    : limits(limits_in), epoch(epoch_in), path_authority(path_authority_in),
      multipath(multipath_in) {}

GroupState* GovernorState::find_group(const ECMPGroupId& id) {
  const auto it = groups.find(id);
  return it == groups.end() ? nullptr : &it->second;
}

const GroupState* GovernorState::find_group(const ECMPGroupId& id) const {
  const auto it = groups.find(id);
  return it == groups.end() ? nullptr : &it->second;
}

void GovernorState::index_paths(const GroupState& group) {
  for (const PathId& path : group.indexed_paths) {
    const auto it = path_index.find(path);
    if (it != path_index.end()) {
      it->second.erase(group.id);
      if (it->second.empty()) {
        path_index.erase(it);
      }
    }
  }
  if (!group.multipath_set.is_nil()) {
    const auto it = multipath_index.find(group.multipath_set);
    if (it != multipath_index.end()) {
      it->second.erase(group.id);
      if (it->second.empty()) {
        multipath_index.erase(it);
      }
    }
  }
}

void GovernorState::unindex_paths(const GroupState& group) {
  for (const PathId& path : group.indexed_paths) {
    const auto it = path_index.find(path);
    if (it != path_index.end()) {
      it->second.erase(group.id);
      if (it->second.empty()) {
        path_index.erase(it);
      }
    }
  }
  if (!group.multipath_set.is_nil()) {
    const auto it = multipath_index.find(group.multipath_set);
    if (it != multipath_index.end()) {
      it->second.erase(group.id);
      if (it->second.empty()) {
        multipath_index.erase(it);
      }
    }
  }
}

void GovernorState::index_group_paths(GroupState& group) {
  index_paths(group);
  if (!group.indexed_authority.is_nil()) {
    const auto authority_it = authority_index.find(group.indexed_authority);
    if (authority_it != authority_index.end()) {
      authority_it->second.erase(group.id);
      if (authority_it->second.empty()) {
        authority_index.erase(authority_it);
      }
    }
  }
  if (!group.authority_publisher.is_nil()) {
    authority_index[group.authority_publisher].insert(group.id);
    group.indexed_authority = group.authority_publisher;
  } else {
    group.indexed_authority = PublisherId{};
  }
  std::vector<PathId> paths;
  paths.reserve(group.members.size());
  for (const MemberEntry& entry : group.members) {
    if (!entry.record.declared) {
      continue;
    }
    if (std::find(paths.begin(), paths.end(), entry.record.path) == paths.end()) {
      paths.push_back(entry.record.path);
    }
  }
  std::sort(paths.begin(), paths.end());
  for (const PathId& path : paths) {
    path_index[path].insert(group.id);
  }
  if (!group.multipath_set.is_nil()) {
    multipath_index[group.multipath_set].insert(group.id);
  }
  group.indexed_paths = std::move(paths);
}

void GovernorState::index_cost_class(GroupState& group) {
  if (group.key.cost_class.is_nil()) {
    return;
  }
  cost_class_index[group.key.cost_class].insert(group.id);
}

void GovernorState::remember_attempt(const MutationAttemptId& attempt, const AttemptEntry& entry) {
  const auto existing = attempts.find(attempt);
  if (existing != attempts.end()) {
    existing->second = entry;
    return;
  }
  attempts.emplace(attempt, entry);
  attempt_order.push_back(attempt);
  while (attempt_order.size() > limits.max_attempts_remembered) {
    attempts.erase(attempt_order.front());
    attempt_order.pop_front();
  }
}

const AttemptEntry* GovernorState::find_attempt(const MutationAttemptId& attempt) const {
  const auto it = attempts.find(attempt);
  return it == attempts.end() ? nullptr : &it->second;
}

void GovernorState::clear_publishers_and_fences() {
  publishers.clear();
  fenced_boots.clear();
}

Digest compute_declared_digest(const GroupState& group) {
  Encoder encoder;
  for (const MemberEntry& entry : group.members) {
    if (entry.record.declared) {
      encoder.raw(entry.record.member.bytes());
    }
  }
  return domain_digest(kDeclaredDigestDomain, encoder.bytes());
}

Digest compute_membership_digest(const GroupState& group) {
  Encoder encoder;
  encoder.u32(static_cast<std::uint32_t>(group.members.size()));
  for (const MemberEntry& entry : group.members) {
    encode_member_record_full(encoder, entry.record);
  }
  return domain_digest(kMembershipDigestDomain, encoder.bytes());
}

Digest compute_semantic_digest(const GroupState& group) {
  Encoder encoder;
  encode_group_identity(encoder, group);
  encoder.u8(static_cast<std::uint8_t>(group.source));
  encoder.u8(static_cast<std::uint8_t>(group.lifecycle));
  encoder.u32(group.currentness.bits());
  encoder.u64(group.membership_generation.value());
  encoder.u64(group.assignment_generation.value());
  encoder.u64(group.authority_generation.value());
  encoder.raw(group.cost_semantics.cost_class.bytes());
  encode_cost_binding(encoder, group.cost_semantics.binding);
  encoder.i64(group.canonical_cost.units);
  encoder.u32(group.canonical_cost.scale);
  encoder.raw(group.hash_domain.bytes());
  encoder.u32(group.bucket_count.value());
  encoder.u32(group.min_active_members);
  encoder.raw(compute_membership_digest(group).bytes());
  encoder.raw(group.assignment.digest().bytes());
  encoder.raw(group.multipath_set.bytes());
  encoder.u64(group.multipath_generation.value());
  encoder.raw(group.provenance.bytes());
  encoder.raw(group.successor.bytes());
  return domain_digest(kSemanticDigestDomain, encoder.bytes());
}

std::optional<Outcome> refresh_group(GovernorState& state, GroupState& group,
                                     const RefreshContext& context, ConditionList& conditions) {
  const MembershipGeneration membership_before = group.membership_generation;
  const AssignmentGeneration assignment_before = group.assignment_generation;
  const AuthorityGeneration authority_before = group.authority_generation;
  const GroupLifecycle lifecycle_before = group.lifecycle;
  const Currentness currentness_before = group.currentness;

  if (context.bind_authority) {
    const bool same_epoch = group.bound_epoch == context.epoch;
    const bool same_publisher = (group.authority_publisher == context.publisher) &&
                                (group.authority_boot == context.worker_boot);
    if (!same_epoch || !same_publisher) {
      const auto next = group.authority_generation.next();
      if (!next.has_value()) {
        conditions.add(make_condition(ConditionCode::GENERATION_EXHAUSTED, "authority_generation"));
        return Outcome::GENERATION_EXHAUSTED;
      }
      group.authority_generation = *next;
      group.bound_epoch = context.epoch;
      group.authority_publisher = context.publisher;
      group.authority_boot = context.worker_boot;
    }
  }

  for (MemberEntry& entry : group.members) {
    MemberInputs inputs;
    inputs.declared = entry.record.declared;
    inputs.administratively_enabled = entry.record.administratively_enabled;
    inputs.upstream_current = entry.upstream_current();
    inputs.retired = false;
    entry.record.state = derive_member_state(inputs);
  }

  const Digest declared_after = compute_declared_digest(group);
  if (!(declared_after == group.declared_digest)) {
    const auto next = group.membership_generation.next();
    if (!next.has_value()) {
      conditions.add(make_condition(ConditionCode::GENERATION_EXHAUSTED, "membership_generation"));
      return Outcome::GENERATION_EXHAUSTED;
    }
    group.membership_generation = *next;
    group.declared_digest = declared_after;
  }

  const std::vector<ECMPMemberId> active = group.active_members();

  if (context.recompute_assignment) {
    const RebalanceComputation computed =
        compute_rebalance(group.assignment, active, group.bucket_count);
    if (!(computed.assignment.owners == group.assignment.owners)) {
      const auto next = group.assignment_generation.next();
      if (!next.has_value()) {
        conditions.add(make_condition(ConditionCode::GENERATION_EXHAUSTED, "assignment_generation"));
        return Outcome::GENERATION_EXHAUSTED;
      }
      group.assignment_generation = *next;
      group.assignment = computed.assignment;
    }
    if (!computed.moves.empty()) {
      RebalanceRecord record;
      record.plan = group.plan.has_value() ? group.plan->plan : RebalancePlanId{};
      record.reason = context.reason;
      record.from_membership = membership_before;
      record.to_membership = group.membership_generation;
      record.from_assignment = assignment_before;
      record.to_assignment = group.assignment_generation;
      record.moves = computed.moves;
      record.churn = computed.churn();
      record.assignment_digest = group.assignment.digest();
      group.last_rebalance = std::move(record);
      ++state.committed_rebalances;
    }
  }

  LifecycleInputs inputs;
  inputs.declared_members = group.declared_count();
  inputs.active_members = static_cast<std::uint32_t>(active.size());
  inputs.min_active_members = group.min_active_members;
  inputs.plan_pending = group.plan.has_value();
  inputs.authority_current = group.currentness.authority_current();

  const std::optional<GroupLifecycle> target =
      apply_group_event(group.lifecycle, context.event, inputs);
  if (!target.has_value()) {
    conditions.add(make_condition(ConditionCode::LIFECYCLE_DENIED,
                                  std::string(to_string(group.lifecycle)),
                                  static_cast<std::uint64_t>(group.lifecycle),
                                  static_cast<std::uint64_t>(context.event)));
    return Outcome::LIFECYCLE_VIOLATION;
  }
  group.lifecycle = *target;

  const bool changed = (group.membership_generation != membership_before) ||
                       (group.assignment_generation != assignment_before) ||
                       (group.authority_generation != authority_before) ||
                       (group.lifecycle != lifecycle_before) ||
                       !(group.currentness == currentness_before);
  if (changed && context.record_history) {
    HistoryEntry entry;
    entry.membership_generation = group.membership_generation;
    entry.assignment_generation = group.assignment_generation;
    entry.authority_generation = group.authority_generation;
    entry.reason = context.reason;
    entry.publisher = context.publisher;
    entry.epoch = context.epoch;
    entry.churn = group.last_rebalance.has_value() &&
                          (group.assignment_generation != assignment_before)
                      ? group.last_rebalance->churn
                      : 0;
    entry.moves_recorded = group.last_rebalance.has_value() &&
                                   (group.assignment_generation != assignment_before)
                               ? group.last_rebalance->moves.size()
                               : 0;
    entry.plan = group.plan.has_value() ? std::optional<RebalancePlanId>(group.plan->plan)
                                        : std::nullopt;
    entry.membership_digest = compute_membership_digest(group);
    entry.assignment_digest = group.assignment.digest();
    group.history.push_back(std::move(entry));
    while (group.history.size() > state.limits.max_history) {
      group.history.pop_front();
    }
  }
  return std::nullopt;
}

GroupSnapshot make_snapshot(const GroupState& group) {
  GroupSnapshot snapshot;
  snapshot.id = group.id;
  snapshot.key = group.key;
  snapshot.source = group.source;
  snapshot.lifecycle = group.lifecycle;
  snapshot.currentness = group.currentness;
  snapshot.membership_generation = group.membership_generation;
  snapshot.assignment_generation = group.assignment_generation;
  snapshot.authority_generation = group.authority_generation;
  snapshot.cost_semantics = group.cost_semantics;
  snapshot.canonical_cost = group.canonical_cost;
  snapshot.hash_domain = group.hash_domain;
  snapshot.bucket_count = group.bucket_count;
  snapshot.min_active_members = group.min_active_members;
  snapshot.members.reserve(group.members.size());
  for (const MemberEntry& entry : group.members) {
    snapshot.members.push_back(entry.record);
    if (entry.record.is_active()) {
      snapshot.active_members.push_back(entry.record.member);
    }
  }
  snapshot.assignment = group.assignment;
  snapshot.multipath_set = group.multipath_set;
  snapshot.multipath_generation = group.multipath_generation;
  snapshot.epoch = group.bound_epoch;
  snapshot.authority_publisher = group.authority_publisher;
  snapshot.provenance = group.provenance;
  snapshot.membership_digest = compute_membership_digest(group);
  snapshot.assignment_digest = group.assignment.digest();
  snapshot.semantic_digest = compute_semantic_digest(group);
  if (group.plan.has_value()) {
    snapshot.pending_plan = group.plan->plan;
  }
  return snapshot;
}

}  // namespace ecmp::detail
