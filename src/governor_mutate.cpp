#include <algorithm>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "ecmp/bytes.hpp"
#include "ecmp/digest.hpp"
#include "ecmp/protocol.hpp"
#include "governor_state.hpp"

namespace ecmp {
namespace {

using detail::GroupState;
using detail::GovernorState;
using detail::MemberEntry;
using detail::RefreshContext;

constexpr std::string_view kAttemptDomain = "ecmp.attempt.v1";

void add_condition(MutationResult& result, ConditionCode code, std::string subject = {},
                   std::uint64_t observed = 0, std::uint64_t expected = 0) {
  result.conditions.add(make_condition(code, std::move(subject), observed, expected));
}

MutationResult reject(Outcome outcome, ConditionCode code, std::string subject = {},
                      std::uint64_t observed = 0, std::uint64_t expected = 0,
                      std::string detail = {}) {
  MutationResult result;
  result.outcome = outcome;
  result.detail = std::move(detail);
  add_condition(result, code, std::move(subject), observed, expected);
  return result;
}

Outcome lifecycle_outcome(GroupLifecycle state) noexcept {
  switch (state) {
    case GroupLifecycle::REVOKED:
      return Outcome::REVOKED;
    case GroupLifecycle::RETIRED:
      return Outcome::RETIRED;
    case GroupLifecycle::WITHDRAWN:
      return Outcome::WITHDRAWN;
    case GroupLifecycle::SUPERSEDED:
      return Outcome::SUPERSEDED;
    default:
      return Outcome::LIFECYCLE_VIOLATION;
  }
}

void fill_group(MutationResult& result, const GroupState& group) {
  result.group = summarize(detail::make_snapshot(group));
}

bool authorize_context(const GovernorState& state, const AuthorityContext& authority,
                       Capability capability, const ECMPGroupId* requested_group,
                       MutationResult& result) {
  if (!authority.is_well_formed()) {
    result = reject(Outcome::MALFORMED_REQUEST, ConditionCode::MALFORMED_IDENTITY,
                    "authority_context");
    return false;
  }
  if (!(authority.epoch == state.epoch)) {
    result = reject(Outcome::STALE_EPOCH, ConditionCode::AUTHORITY_EPOCH_STALE, "epoch",
                    authority.epoch.value(), state.epoch.value());
    return false;
  }
  const auto it = state.publishers.find(authority.publisher);
  if (it == state.publishers.end()) {
    result = reject(Outcome::UNAUTHORIZED, ConditionCode::PUBLISHER_UNKNOWN, "publisher");
    return false;
  }
  if (state.fenced_boots.count(authority.worker_boot) != 0) {
    result = reject(Outcome::STALE_WORKER, ConditionCode::WORKER_FENCED, "worker_boot");
    return false;
  }
  if (!(it->second.registration.worker_boot == authority.worker_boot)) {
    result = reject(Outcome::STALE_WORKER, ConditionCode::WORKER_FENCED, "worker_boot");
    return false;
  }
  if (!has_capability(it->second.registration.capabilities, capability)) {
    result = reject(Outcome::UNAUTHORIZED, ConditionCode::CAPABILITY_MISSING,
                    std::string(to_string(capability)), it->second.registration.capabilities,
                    static_cast<std::uint64_t>(capability));
    return false;
  }
  if (authority.scope.kind == ScopeKind::DENY_ALL) {
    result = reject(Outcome::UNAUTHORIZED, ConditionCode::SCOPE_DENIED, "DENY_ALL");
    return false;
  }
  // A group-scoped grant can be checked before the group is even looked up.
  if (authority.scope.kind == ScopeKind::GROUP && requested_group != nullptr &&
      !(authority.scope.group == *requested_group)) {
    result = reject(Outcome::UNAUTHORIZED, ConditionCode::SCOPE_DENIED,
                    authority.scope.render());
    return false;
  }
  return true;
}

bool authorize_scope(const AuthorityContext& authority, const GroupKey& key,
                     const ECMPGroupId& group_id, MutationResult& result) {
  if (authority.scope.covers(key, group_id)) {
    return true;
  }
  result = reject(Outcome::UNAUTHORIZED, ConditionCode::SCOPE_DENIED, authority.scope.render());
  return false;
}

bool handle_attempt(GovernorState& state, const AuthorityContext& authority, const Digest& payload,
                    const ECMPGroupId& group_id, MutationResult& result) {
  const detail::AttemptEntry* existing = state.find_attempt(authority.attempt);
  if (existing == nullptr) {
    return false;
  }
  if (!(existing->payload == payload)) {
    result = reject(Outcome::ATTEMPT_CONFLICT, ConditionCode::ATTEMPT_CONFLICT,
                    authority.attempt.to_text());
    return true;
  }
  result = MutationResult{};
  result.outcome = Outcome::IDEMPOTENT;
  result.detail = existing->detail;
  add_condition(result, ConditionCode::ATTEMPT_REPLAY, authority.attempt.to_text(),
                static_cast<std::uint64_t>(existing->outcome));
  const GroupState* group = state.find_group(group_id);
  if (group != nullptr) {
    fill_group(result, *group);
  }
  return true;
}

void remember_attempt(GovernorState& state, const AuthorityContext& authority, const Digest& payload,
                      const ECMPGroupId& group_id, const MutationResult& result) {
  detail::AttemptEntry entry;
  entry.payload = payload;
  entry.outcome = result.outcome;
  entry.group = group_id;
  entry.primary =
      result.conditions.empty() ? ConditionCode::NONE : result.conditions.entries().front().code;
  entry.detail = result.detail;
  state.remember_attempt(authority.attempt, entry);
}

bool check_expected(const GroupState& group, const AuthorityContext& authority,
                    MutationResult& result) {
  if (authority.expected_membership.has_value() &&
      !(*authority.expected_membership == group.membership_generation)) {
    result = reject(Outcome::STALE_GROUP_GENERATION, ConditionCode::EXPECTED_MEMBERSHIP_MISMATCH,
                    "membership_generation", group.membership_generation.value(),
                    authority.expected_membership->value());
    return false;
  }
  if (authority.expected_assignment.has_value() &&
      !(*authority.expected_assignment == group.assignment_generation)) {
    result =
        reject(Outcome::STALE_ASSIGNMENT_GENERATION, ConditionCode::EXPECTED_ASSIGNMENT_MISMATCH,
               "assignment_generation", group.assignment_generation.value(),
               authority.expected_assignment->value());
    return false;
  }
  if (authority.expected_authority.has_value() &&
      !(*authority.expected_authority == group.authority_generation)) {
    result = reject(Outcome::STALE_AUTHORITY_GENERATION, ConditionCode::EXPECTED_AUTHORITY_MISMATCH,
                    "authority_generation", group.authority_generation.value(),
                    authority.expected_authority->value());
    return false;
  }
  return true;
}

bool check_lifecycle(const GroupState& group, GroupEvent event, MutationResult& result) {
  if (lifecycle_allows(group.lifecycle, event)) {
    return true;
  }
  result = reject(lifecycle_outcome(group.lifecycle), ConditionCode::LIFECYCLE_DENIED,
                  std::string(to_string(group.lifecycle)),
                  static_cast<std::uint64_t>(group.lifecycle),
                  static_cast<std::uint64_t>(event));
  return false;
}

enum class UpstreamStatus : std::uint32_t {
  OK = 0,
  PATH_UNKNOWN = 1,
  PATH_STALE = 2,
  PATH_UNAUTHORIZED = 3,
  MULTIPATH_UNKNOWN = 4,
  MULTIPATH_STALE = 5,
  MULTIPATH_ABSENT = 6,
};

struct UpstreamCheck {
  UpstreamStatus status = UpstreamStatus::OK;
  PathAuthorityGeneration observed;
};

UpstreamCheck check_upstream(const GovernorState& state, const MemberSpec& spec,
                             MembershipSource source, const MultipathSetId& set,
                             MultipathSetGeneration generation) {
  UpstreamCheck check;
  if (state.path_authority == nullptr) {
    check.status = UpstreamStatus::PATH_UNKNOWN;
    return check;
  }
  const auto observation = state.path_authority->observe(spec.path);
  if (!observation.has_value()) {
    check.status = UpstreamStatus::PATH_UNKNOWN;
    return check;
  }
  check.observed = observation->generation;
  if (!(observation->generation == spec.path_authority)) {
    check.status = UpstreamStatus::PATH_STALE;
    return check;
  }
  if (!observation->authorized) {
    check.status = UpstreamStatus::PATH_UNAUTHORIZED;
    return check;
  }
  if (source == MembershipSource::MULTIPATH_FABRIC) {
    if (state.multipath == nullptr) {
      check.status = UpstreamStatus::MULTIPATH_UNKNOWN;
      return check;
    }
    const auto current = state.multipath->generation(set);
    if (!current.has_value()) {
      check.status = UpstreamStatus::MULTIPATH_UNKNOWN;
      return check;
    }
    if (!(*current == generation)) {
      check.status = UpstreamStatus::MULTIPATH_STALE;
      return check;
    }
    if (!state.multipath->contains(set, generation, spec.path)) {
      check.status = UpstreamStatus::MULTIPATH_ABSENT;
      return check;
    }
  }
  return check;
}

MutationResult upstream_rejection(const UpstreamCheck& check, const PathId& path) {
  switch (check.status) {
    case UpstreamStatus::PATH_UNKNOWN:
      return reject(Outcome::STALE_PATH_AUTHORITY, ConditionCode::PATH_AUTHORITY_UNKNOWN,
                    path.to_text());
    case UpstreamStatus::PATH_STALE:
      return reject(Outcome::STALE_PATH_AUTHORITY, ConditionCode::PATH_AUTHORITY_STALE,
                    path.to_text(), check.observed.value(), 0);
    case UpstreamStatus::PATH_UNAUTHORIZED:
      return reject(Outcome::STALE_PATH_AUTHORITY, ConditionCode::PATH_AUTHORITY_STALE,
                    path.to_text(), check.observed.value(), 0);
    case UpstreamStatus::MULTIPATH_UNKNOWN:
    case UpstreamStatus::MULTIPATH_STALE:
      return reject(Outcome::STALE_MULTIPATH_SET, ConditionCode::MULTIPATH_SET_STALE,
                    path.to_text());
    case UpstreamStatus::MULTIPATH_ABSENT:
      return reject(Outcome::STALE_MULTIPATH_SET, ConditionCode::MULTIPATH_MEMBER_ABSENT,
                    path.to_text());
    case UpstreamStatus::OK:
      break;
  }
  return MutationResult{};
}

std::optional<MutationResult> cost_rejection(const CostSemantics& semantics,
                                             const PathCost& reference, const CostClaim& claim,
                                             const ECMPMemberId& member) {
  switch (compare_cost_claim(semantics, reference, claim)) {
    case CostCompatibility::EQUAL:
      return std::nullopt;
    case CostCompatibility::CLASS_MISMATCH:
      return reject(Outcome::COST_CLASS_MISMATCH, ConditionCode::COST_CLASS_MISMATCH,
                    member.to_text());
    case CostCompatibility::MODEL_MISMATCH:
      return reject(Outcome::COST_CLASS_MISMATCH, ConditionCode::COST_MODEL_MISMATCH,
                    member.to_text(), claim.binding.model_version,
                    semantics.binding.model_version);
    case CostCompatibility::POLICY_STALE:
      return reject(Outcome::STALE_COST_GENERATION, ConditionCode::COST_POLICY_STALE,
                    member.to_text(), claim.binding.policy_generation.value(),
                    semantics.binding.policy_generation.value());
    case CostCompatibility::VALUE_MISMATCH:
      return reject(Outcome::COST_MISMATCH, ConditionCode::COST_VALUE_MISMATCH, member.to_text(),
                    static_cast<std::uint64_t>(claim.cost.units),
                    static_cast<std::uint64_t>(reference.units));
  }
  return std::nullopt;
}

std::optional<MutationResult> validate_spec(const GovernorState& state, const MemberSpec& spec,
                                            const CostSemantics& semantics,
                                            const PathCost& canonical, MembershipSource source,
                                            const MultipathSetId& set,
                                            MultipathSetGeneration generation) {
  if (!spec.is_well_formed()) {
    return reject(Outcome::MALFORMED_REQUEST, ConditionCode::MALFORMED_IDENTITY,
                  spec.member.to_text());
  }
  const UpstreamCheck check = check_upstream(state, spec, source, set, generation);
  if (check.status != UpstreamStatus::OK) {
    return upstream_rejection(check, spec.path);
  }
  return cost_rejection(semantics, canonical, spec.cost, spec.member);
}

void reobserve_member(const GovernorState& state, const GroupState& group, MemberEntry& entry) {
  entry.path_authority_current = false;
  entry.path_authority_authorized = false;
  if (state.path_authority != nullptr) {
    const auto observation = state.path_authority->observe(entry.record.path);
    if (observation.has_value()) {
      entry.path_authority_authorized = observation->authorized;
      entry.path_authority_current =
          observation->authorized && (observation->generation == entry.record.path_authority);
    }
  }
  entry.multipath_current = true;
  if (group.source == MembershipSource::MULTIPATH_FABRIC) {
    entry.multipath_current = false;
    if (state.multipath != nullptr && !group.multipath_set.is_nil()) {
      const auto current = state.multipath->generation(group.multipath_set);
      if (current.has_value() && (*current == group.multipath_generation)) {
        entry.multipath_current = state.multipath->contains(
            group.multipath_set, group.multipath_generation, entry.record.path);
      }
    }
  }
}

void reobserve_group(const GovernorState& state, GroupState& group) {
  bool path_stale = false;
  for (MemberEntry& entry : group.members) {
    if (!entry.record.declared) {
      continue;
    }
    reobserve_member(state, group, entry);
    if (!entry.path_authority_current) {
      path_stale = true;
    }
  }
  if (path_stale) {
    group.currentness.add(CurrentnessCause::STALE_PATH_AUTHORITY);
  } else {
    group.currentness.remove(CurrentnessCause::STALE_PATH_AUTHORITY);
  }
  bool multipath_stale = false;
  if (group.source == MembershipSource::MULTIPATH_FABRIC) {
    for (const MemberEntry& entry : group.members) {
      if (entry.record.declared && !entry.multipath_current) {
        multipath_stale = true;
        break;
      }
    }
  }
  if (multipath_stale) {
    group.currentness.add(CurrentnessCause::STALE_MULTIPATH_SET);
  } else {
    group.currentness.remove(CurrentnessCause::STALE_MULTIPATH_SET);
  }
}

void evict_withdrawn(GovernorState& state, GroupState& group) {
  while (group.members.size() > state.limits.max_members_per_group) {
    bool evicted = false;
    for (std::size_t index = 0; index < group.members.size(); ++index) {
      if (!group.members[index].record.declared) {
        group.members.erase(group.members.begin() + static_cast<std::ptrdiff_t>(index));
        evicted = true;
        break;
      }
    }
    if (!evicted) {
      break;
    }
  }
}

void sort_members(std::vector<MemberEntry>& members) {
  std::stable_sort(members.begin(), members.end(),
                   [](const MemberEntry& left, const MemberEntry& right) {
                     return std::tie(left.record.path, left.record.member) <
                            std::tie(right.record.path, right.record.member);
                   });
}

bool valid_bucket_count(const GovernorLimits& limits, BucketCount count) {
  return count.is_valid() && count.value() <= limits.max_buckets;
}

MemberSpec spec_of(const MemberRecord& record) {
  MemberSpec spec;
  spec.member = record.member;
  spec.path = record.path;
  spec.path_authority = record.path_authority;
  spec.member_generation = record.member_generation;
  spec.cost = record.cost;
  spec.provenance = record.provenance;
  spec.administratively_enabled = record.administratively_enabled;
  return spec;
}

struct GroupPreamble {
  MutationResult result;
  GroupState* group = nullptr;
  std::uint32_t declared_before = 0;
};

bool group_preamble(GovernorState& state, const AuthorityContext& authority, const ECMPGroupId& id,
                    Capability capability, const Digest& payload, GroupEvent event,
                    GroupPreamble& out) {
  if (!authorize_context(state, authority, capability, &id, out.result)) {
    return false;
  }
  GroupState* group = state.find_group(id);
  if (group == nullptr) {
    out.result = reject(Outcome::UNKNOWN_GROUP, ConditionCode::GROUP_UNKNOWN, id.to_text());
    return false;
  }
  if (!authorize_scope(authority, group->key, id, out.result)) {
    return false;
  }
  if (handle_attempt(state, authority, payload, id, out.result)) {
    return false;
  }
  if (!check_lifecycle(*group, event, out.result)) {
    return false;
  }
  if (!check_expected(*group, authority, out.result)) {
    return false;
  }
  out.group = group;
  out.declared_before = group->declared_count();
  return true;
}

RefreshContext make_context(const GovernorState& state, const AuthorityContext& authority,
                            ChangeReason reason, GroupEvent event) {
  RefreshContext context;
  context.reason = reason;
  context.event = event;
  context.publisher = authority.publisher;
  context.worker_boot = authority.worker_boot;
  context.epoch = state.epoch;
  context.bind_authority = true;
  return context;
}

MutationResult finish_group_mutation(GovernorState& state, GroupState& group,
                                     std::uint32_t declared_before, RefreshContext context,
                                     const AuthorityContext& authority, const Digest& payload,
                                     Outcome success, std::string detail = {}) {
  ConditionList conditions(state.limits.max_explanation_entries);
  const auto failure = detail::refresh_group(state, group, context, conditions);
  if (failure.has_value()) {
    MutationResult result;
    result.outcome = *failure;
    result.conditions = conditions;
    return result;
  }
  const std::uint32_t declared_after = group.declared_count();
  if (declared_after >= declared_before) {
    state.total_members += static_cast<std::uint64_t>(declared_after - declared_before);
  } else {
    state.total_members -= static_cast<std::uint64_t>(declared_before - declared_after);
  }
  evict_withdrawn(state, group);
  state.index_group_paths(group);
  MutationResult result;
  result.outcome = success;
  result.detail = std::move(detail);
  fill_group(result, group);
  remember_attempt(state, authority, payload, group.id, result);
  return result;
}

MutationResult no_change(GovernorState& state, GroupState& group, const AuthorityContext& authority,
                         const Digest& payload) {
  MutationResult result;
  result.outcome = Outcome::NO_CHANGE;
  fill_group(result, group);
  remember_attempt(state, authority, payload, group.id, result);
  return result;
}

bool authorize_upstream(const GovernorState& state, CoordinatorEpoch epoch,
                        const PublisherId& publisher, const WorkerBootId& worker_boot,
                        MutationResult& result) {
  if (publisher.is_nil() || worker_boot.is_nil()) {
    result = reject(Outcome::MALFORMED_REQUEST, ConditionCode::MALFORMED_IDENTITY, "upstream_feed");
    return false;
  }
  if (!(epoch == state.epoch)) {
    result = reject(Outcome::STALE_EPOCH, ConditionCode::AUTHORITY_EPOCH_STALE, "epoch",
                    epoch.value(), state.epoch.value());
    return false;
  }
  const auto it = state.publishers.find(publisher);
  if (it == state.publishers.end()) {
    result = reject(Outcome::UNAUTHORIZED, ConditionCode::PUBLISHER_UNKNOWN, "publisher");
    return false;
  }
  if (!(it->second.registration.worker_boot == worker_boot) ||
      state.fenced_boots.count(worker_boot) != 0) {
    result = reject(Outcome::STALE_WORKER, ConditionCode::WORKER_FENCED, "worker_boot");
    return false;
  }
  if (!has_capability(it->second.registration.capabilities, Capability::PUBLISH_UPSTREAM)) {
    result = reject(Outcome::UNAUTHORIZED, ConditionCode::CAPABILITY_MISSING, "PUBLISH_UPSTREAM");
    return false;
  }
  return true;
}

const AuthorityScope& scope_of(const GovernorState& state, const PublisherId& publisher) {
  static const AuthorityScope kDenyAll{};
  const auto it = state.publishers.find(publisher);
  if (it == state.publishers.end()) {
    return kDenyAll;
  }
  return it->second.registration.scope;
}

}  // namespace

MutationResult EcmpGovernor::create_group(const CreateGroupRequest& request) {
  std::unique_lock lock(state_->mutex);
  GovernorState& state = *state_;
  const AuthorityContext& authority = request.authority;
  const Digest payload = domain_digest(kAttemptDomain, encode_payload(request));
  MutationResult result;

  if (!authorize_context(state, authority, Capability::MUTATE_GROUP, &request.group, result)) {
    return result;
  }
  if (handle_attempt(state, authority, payload, request.group, result)) {
    return result;
  }
  if (request.group.is_nil()) {
    return reject(Outcome::MALFORMED_REQUEST, ConditionCode::MALFORMED_IDENTITY, "group");
  }
  if (!request.key.is_well_formed()) {
    return reject(Outcome::MALFORMED_REQUEST, ConditionCode::MALFORMED_IDENTITY, "group_key");
  }
  if (!authorize_scope(authority, request.key, request.group, result)) {
    return result;
  }
  if (!request.cost_semantics.is_well_formed()) {
    return reject(Outcome::MALFORMED_REQUEST, ConditionCode::MALFORMED_IDENTITY, "cost_semantics");
  }
  if (request.cost_semantics.cost_class != request.key.cost_class) {
    return reject(Outcome::MALFORMED_REQUEST, ConditionCode::COST_CLASS_MISMATCH, "group_key");
  }
  if (request.hash_domain.is_nil() || request.provenance.is_nil()) {
    return reject(Outcome::MALFORMED_REQUEST, ConditionCode::MALFORMED_IDENTITY, "group_metadata");
  }
  if (request.source == MembershipSource::MULTIPATH_FABRIC && request.multipath_set.is_nil()) {
    return reject(Outcome::MALFORMED_REQUEST, ConditionCode::MALFORMED_IDENTITY, "multipath_set");
  }
  if (request.min_active_members == 0) {
    return reject(Outcome::MALFORMED_REQUEST, ConditionCode::MIN_ACTIVE_NOT_MET,
                  "min_active_members", 0, 1);
  }
  if (!request.bucket_count.is_valid()) {
    return reject(Outcome::MALFORMED_REQUEST, ConditionCode::BUCKET_LIMIT, "bucket_count", 0,
                  state.limits.max_buckets);
  }
  if (!valid_bucket_count(state.limits, request.bucket_count)) {
    return reject(Outcome::RESOURCE_LIMIT, ConditionCode::BUCKET_LIMIT, "bucket_count",
                  request.bucket_count.value(), state.limits.max_buckets);
  }
  if (request.min_active_members > state.limits.max_members_per_group) {
    return reject(Outcome::RESOURCE_LIMIT, ConditionCode::MEMBER_SET_LIMIT, "min_active_members",
                  request.min_active_members, state.limits.max_members_per_group);
  }
  if (request.members.size() > state.limits.max_members_per_group) {
    return reject(Outcome::RESOURCE_LIMIT, ConditionCode::MEMBER_SET_LIMIT, "members",
                  request.members.size(), state.limits.max_members_per_group);
  }
  if (request.members.size() > request.bucket_count.value()) {
    return reject(Outcome::RESOURCE_LIMIT, ConditionCode::BUCKET_LIMIT, "members",
                  request.members.size(), request.bucket_count.value());
  }
  if (request.members.size() < request.min_active_members) {
    return reject(Outcome::INSUFFICIENT_MEMBERS, ConditionCode::MIN_ACTIVE_NOT_MET, "members",
                  request.members.size(), request.min_active_members);
  }
  if (state.groups.size() >= state.limits.max_groups) {
    return reject(Outcome::RESOURCE_LIMIT, ConditionCode::GROUP_LIMIT, "groups",
                  state.groups.size(), state.limits.max_groups);
  }
  if (state.total_members + request.members.size() > state.limits.max_total_members) {
    return reject(Outcome::RESOURCE_LIMIT, ConditionCode::GROUP_LIMIT, "total_members",
                  state.total_members, state.limits.max_total_members);
  }
  if (state.groups.find(request.group) != state.groups.end()) {
    return reject(Outcome::DUPLICATE_GROUP, ConditionCode::GROUP_DUPLICATE,
                  request.group.to_text());
  }
  if (state.key_index.find(request.key) != state.key_index.end()) {
    return reject(Outcome::DUPLICATE_GROUP, ConditionCode::GROUP_DUPLICATE, "group_key");
  }

  std::vector<MemberEntry> entries;
  entries.reserve(request.members.size());
  for (const MemberSpec& spec : request.members) {
    for (const MemberEntry& existing : entries) {
      if (existing.record.member == spec.member) {
        return reject(Outcome::DUPLICATE_MEMBER, ConditionCode::MEMBER_DUPLICATE,
                      spec.member.to_text());
      }
    }
    const auto invalid = validate_spec(state, spec, request.cost_semantics,
                                       request.members.front().cost.cost, request.source,
                                       request.multipath_set, request.multipath_generation);
    if (invalid.has_value()) {
      return *invalid;
    }
    MemberEntry entry;
    entry.record = detail::make_record(spec, spec.administratively_enabled);
    entry.path_authority_current = true;
    entry.path_authority_authorized = true;
    entry.multipath_current = true;
    entry.cost_current = true;
    entries.push_back(std::move(entry));
  }

  std::uint32_t eligible = 0;
  for (const MemberEntry& entry : entries) {
    if (entry.record.administratively_enabled) {
      ++eligible;
    }
  }
  if (eligible < request.min_active_members) {
    return reject(Outcome::INSUFFICIENT_MEMBERS, ConditionCode::MIN_ACTIVE_NOT_MET, "eligible",
                  eligible, request.min_active_members);
  }

  sort_members(entries);

  GroupState group;
  group.id = request.group;
  group.key = request.key;
  group.source = request.source;
  group.lifecycle = GroupLifecycle::DECLARED;
  group.cost_semantics = request.cost_semantics;
  group.canonical_cost = request.members.front().cost.cost;
  group.hash_domain = request.hash_domain;
  group.bucket_count = request.bucket_count;
  group.min_active_members = request.min_active_members;
  group.members = std::move(entries);
  group.assignment.count = request.bucket_count;
  group.assignment.owners.assign(request.bucket_count.value(), ECMPMemberId{});
  group.multipath_set = request.source == MembershipSource::MULTIPATH_FABRIC ? request.multipath_set
                                                                            : MultipathSetId{};
  group.multipath_generation = request.multipath_generation;
  group.authority_publisher = authority.publisher;
  group.authority_boot = authority.worker_boot;
  group.bound_epoch = state.epoch;
  group.provenance = request.provenance;
  group.authority_generation = AuthorityGeneration::from_value(1);

  RefreshContext context = make_context(state, authority, ChangeReason::CREATE,
                                        GroupEvent::ADD_MEMBER);
  ConditionList conditions(state.limits.max_explanation_entries);
  const auto failure = detail::refresh_group(state, group, context, conditions);
  if (failure.has_value()) {
    result.outcome = *failure;
    result.conditions = conditions;
    return result;
  }

  state.total_members += group.declared_count();
  state.index_group_paths(group);
  state.index_cost_class(group);
  state.key_index.emplace(group.key, group.id);
  const ECMPGroupId created = group.id;
  state.groups.emplace(created, std::move(group));

  result = MutationResult{};
  result.outcome = Outcome::CREATED;
  fill_group(result, state.groups.at(created));
  remember_attempt(state, authority, payload, created, result);
  return result;
}

MutationResult EcmpGovernor::add_member(const AddMemberRequest& request) {
  std::unique_lock lock(state_->mutex);
  GovernorState& state = *state_;
  const Digest payload = domain_digest(kAttemptDomain, encode_payload(request));
  GroupPreamble preamble;
  if (!group_preamble(state, request.authority, request.group, Capability::MUTATE_GROUP, payload,
                      GroupEvent::ADD_MEMBER, preamble)) {
    return preamble.result;
  }
  GroupState& group = *preamble.group;
  const MemberSpec& spec = request.member;
  MemberEntry* existing = group.find_member(spec.member);
  if (existing != nullptr && existing->record.declared) {
    return reject(Outcome::DUPLICATE_MEMBER, ConditionCode::MEMBER_DUPLICATE,
                  spec.member.to_text());
  }
  if (group.declared_count() + 1 > state.limits.max_members_per_group) {
    return reject(Outcome::RESOURCE_LIMIT, ConditionCode::MEMBER_SET_LIMIT, "declared_members",
                  group.declared_count() + 1, state.limits.max_members_per_group);
  }
  if (group.declared_count() + 1 > group.bucket_count.value()) {
    return reject(Outcome::RESOURCE_LIMIT, ConditionCode::BUCKET_LIMIT, "declared_members",
                  group.declared_count() + 1, group.bucket_count.value());
  }
  if (state.total_members + 1 > state.limits.max_total_members) {
    return reject(Outcome::RESOURCE_LIMIT, ConditionCode::GROUP_LIMIT, "total_members",
                  state.total_members + 1, state.limits.max_total_members);
  }
  const auto invalid =
      validate_spec(state, spec, group.cost_semantics, group.canonical_cost, group.source,
                    group.multipath_set, group.multipath_generation);
  if (invalid.has_value()) {
    return *invalid;
  }

  MemberEntry entry;
  entry.record = detail::make_record(spec, spec.administratively_enabled);
  entry.path_authority_current = true;
  entry.path_authority_authorized = true;
  entry.multipath_current = true;
  entry.cost_current = true;
  if (existing != nullptr) {
    *existing = std::move(entry);
  } else {
    group.members.push_back(std::move(entry));
  }
  sort_members(group.members);

  RefreshContext context =
      make_context(state, request.authority, ChangeReason::ADD_MEMBER, GroupEvent::ADD_MEMBER);
  return finish_group_mutation(state, group, preamble.declared_before, context, request.authority,
                               payload, Outcome::MEMBER_ADDED);
}

MutationResult EcmpGovernor::remove_member(const RemoveMemberRequest& request) {
  std::unique_lock lock(state_->mutex);
  GovernorState& state = *state_;
  const Digest payload = domain_digest(kAttemptDomain, encode_payload(request));
  GroupPreamble preamble;
  if (!group_preamble(state, request.authority, request.group, Capability::MUTATE_GROUP, payload,
                      GroupEvent::REMOVE_MEMBER, preamble)) {
    return preamble.result;
  }
  GroupState& group = *preamble.group;
  MemberEntry* entry = group.find_member(request.member);
  if (entry == nullptr) {
    return reject(Outcome::UNKNOWN_MEMBER, ConditionCode::MEMBER_UNKNOWN,
                  request.member.to_text());
  }
  if (!entry->record.declared) {
    return reject(Outcome::UNKNOWN_MEMBER, ConditionCode::MEMBER_WITHDRAWN,
                  request.member.to_text());
  }
  entry->record.declared = false;
  entry->record.administratively_enabled = true;
  entry->path_authority_current = true;
  entry->multipath_current = true;
  entry->cost_current = true;

  RefreshContext context = make_context(state, request.authority, ChangeReason::REMOVE_MEMBER,
                                        GroupEvent::REMOVE_MEMBER);
  return finish_group_mutation(state, group, preamble.declared_before, context, request.authority,
                               payload, Outcome::MEMBER_REMOVED);
}

MutationResult EcmpGovernor::set_member_enabled(const SetMemberEnabledRequest& request) {
  std::unique_lock lock(state_->mutex);
  GovernorState& state = *state_;
  const Digest payload = domain_digest(kAttemptDomain, encode_payload(request));
  const GroupEvent event =
      request.enabled ? GroupEvent::ENABLE_MEMBER : GroupEvent::DISABLE_MEMBER;
  GroupPreamble preamble;
  if (!group_preamble(state, request.authority, request.group, Capability::MUTATE_GROUP, payload,
                      event, preamble)) {
    return preamble.result;
  }
  GroupState& group = *preamble.group;
  MemberEntry* entry = group.find_member(request.member);
  if (entry == nullptr) {
    return reject(Outcome::UNKNOWN_MEMBER, ConditionCode::MEMBER_UNKNOWN,
                  request.member.to_text());
  }
  if (!entry->record.declared) {
    return reject(Outcome::UNKNOWN_MEMBER, ConditionCode::MEMBER_WITHDRAWN,
                  request.member.to_text());
  }
  if (entry->record.administratively_enabled == request.enabled) {
    return no_change(state, group, request.authority, payload);
  }
  if (request.enabled) {
    // Re-enabling is never a blind restoration: the current Path Authority
    // binding, multipath binding and cost policy must all still be current.
    if (group.currentness.has(CurrentnessCause::STALE_COST_CLASS)) {
      return reject(Outcome::STALE_COST_GENERATION, ConditionCode::COST_POLICY_STALE,
                    request.member.to_text());
    }
    const auto invalid = validate_spec(state, spec_of(entry->record), group.cost_semantics,
                                       group.canonical_cost, group.source, group.multipath_set,
                                       group.multipath_generation);
    if (invalid.has_value()) {
      return *invalid;
    }
    entry->path_authority_current = true;
    entry->path_authority_authorized = true;
    entry->multipath_current = true;
    entry->cost_current = true;
  }
  entry->record.administratively_enabled = request.enabled;

  RefreshContext context =
      make_context(state, request.authority,
                   request.enabled ? ChangeReason::ENABLE_MEMBER : ChangeReason::DISABLE_MEMBER,
                   event);
  return finish_group_mutation(state, group, preamble.declared_before, context, request.authority,
                               payload,
                               request.enabled ? Outcome::MEMBER_ENABLED
                                               : Outcome::MEMBER_DISABLED);
}

MutationResult EcmpGovernor::apply_membership_set(const MembershipSetRequest& request) {
  std::unique_lock lock(state_->mutex);
  GovernorState& state = *state_;
  const Digest payload = domain_digest(kAttemptDomain, encode_payload(request));
  GroupPreamble preamble;
  if (!group_preamble(state, request.authority, request.group, Capability::MUTATE_GROUP, payload,
                      GroupEvent::ADD_MEMBER, preamble)) {
    return preamble.result;
  }
  GroupState& group = *preamble.group;

  for (std::size_t left = 0; left < request.members.size(); ++left) {
    if (!request.members[left].is_well_formed()) {
      return reject(Outcome::MALFORMED_REQUEST, ConditionCode::MALFORMED_IDENTITY,
                    request.members[left].member.to_text());
    }
    for (std::size_t right = left + 1; right < request.members.size(); ++right) {
      if (request.members[left].member == request.members[right].member) {
        return reject(Outcome::DUPLICATE_MEMBER, ConditionCode::MEMBER_DUPLICATE,
                      request.members[left].member.to_text());
      }
    }
  }
  if (request.members.size() > state.limits.max_members_per_group) {
    return reject(Outcome::RESOURCE_LIMIT, ConditionCode::MEMBER_SET_LIMIT, "members",
                  request.members.size(), state.limits.max_members_per_group);
  }
  if (request.members.size() > group.bucket_count.value()) {
    return reject(Outcome::RESOURCE_LIMIT, ConditionCode::BUCKET_LIMIT, "members",
                  request.members.size(), group.bucket_count.value());
  }

  std::uint32_t changes = 0;
  for (const MemberSpec& spec : request.members) {
    const MemberEntry* existing = group.find_member(spec.member);
    if (existing == nullptr || !existing->record.declared) {
      ++changes;
      continue;
    }
    if (!(existing->record.path == spec.path)) {
      return reject(Outcome::MALFORMED_REQUEST, ConditionCode::MALFORMED_PAYLOAD,
                    spec.member.to_text());
    }
    if (existing->record.administratively_enabled != spec.administratively_enabled ||
        !(existing->record.path_authority == spec.path_authority) ||
        !(existing->record.member_generation == spec.member_generation) ||
        !(existing->record.cost == spec.cost)) {
      ++changes;
    }
  }
  for (const MemberEntry& entry : group.members) {
    if (!entry.record.declared) {
      continue;
    }
    const bool present =
        std::any_of(request.members.begin(), request.members.end(),
                    [&entry](const MemberSpec& spec) { return spec.member == entry.record.member; });
    if (!present) {
      ++changes;
    }
  }
  if (changes > state.limits.max_batch_size) {
    return reject(Outcome::RESOURCE_LIMIT, ConditionCode::BATCH_LIMIT, "changes", changes,
                  state.limits.max_batch_size);
  }
  for (const MemberSpec& spec : request.members) {
    const auto invalid =
        validate_spec(state, spec, group.cost_semantics, group.canonical_cost, group.source,
                      group.multipath_set, group.multipath_generation);
    if (invalid.has_value()) {
      return *invalid;
    }
  }

  GroupState trial = group;
  const std::uint64_t committed_before = state.committed_rebalances;
  std::uint32_t added = 0;
  std::uint32_t removed = 0;

  for (MemberEntry& entry : trial.members) {
    if (!entry.record.declared) {
      continue;
    }
    const auto spec = std::find_if(
        request.members.begin(), request.members.end(),
        [&entry](const MemberSpec& candidate) { return candidate.member == entry.record.member; });
    if (spec == request.members.end()) {
      entry.record.declared = false;
      entry.record.administratively_enabled = true;
      ++removed;
    }
  }
  for (const MemberSpec& spec : request.members) {
    MemberEntry* entry = trial.find_member(spec.member);
    if (entry == nullptr) {
      MemberEntry fresh;
      fresh.record = detail::make_record(spec, spec.administratively_enabled);
      fresh.path_authority_current = true;
      fresh.path_authority_authorized = true;
      fresh.multipath_current = true;
      fresh.cost_current = true;
      trial.members.push_back(std::move(fresh));
      ++added;
      continue;
    }
    if (!entry->record.declared) {
      ++added;
    }
    entry->record = detail::make_record(spec, spec.administratively_enabled);
    entry->path_authority_current = true;
    entry->path_authority_authorized = true;
    entry->multipath_current = true;
    entry->cost_current = true;
  }
  sort_members(trial.members);

  RefreshContext context =
      make_context(state, request.authority,
                   added > 0 ? ChangeReason::ADD_MEMBER : ChangeReason::REMOVE_MEMBER,
                   added > 0 ? GroupEvent::ADD_MEMBER : GroupEvent::REMOVE_MEMBER);
  ConditionList conditions(state.limits.max_explanation_entries);
  const auto failure = detail::refresh_group(state, trial, context, conditions);
  if (failure.has_value()) {
    state.committed_rebalances = committed_before;
    MutationResult result;
    result.outcome = *failure;
    result.conditions = conditions;
    return result;
  }
  const bool assignment_changed = trial.assignment_generation != group.assignment_generation;
  const std::uint64_t churn =
      assignment_changed && trial.last_rebalance.has_value() ? trial.last_rebalance->churn : 0;
  if (churn > state.limits.max_rebalance_moves) {
    state.committed_rebalances = committed_before;
    return reject(Outcome::RESOURCE_LIMIT, ConditionCode::CHURN_LIMIT, "churn", churn,
                  state.limits.max_rebalance_moves);
  }

  group = std::move(trial);
  const std::uint32_t declared_after = group.declared_count();
  if (declared_after >= preamble.declared_before) {
    state.total_members += static_cast<std::uint64_t>(declared_after - preamble.declared_before);
  } else {
    state.total_members -= static_cast<std::uint64_t>(preamble.declared_before - declared_after);
  }
  evict_withdrawn(state, group);
  state.index_group_paths(group);

  MutationResult result;
  result.outcome = assignment_changed ? Outcome::REBALANCED : Outcome::NO_CHANGE;
  fill_group(result, group);
  remember_attempt(state, request.authority, payload, group.id, result);
  return result;
}

namespace {

void reobserve_member_path(const GovernorState& state, MemberEntry& entry) {
  entry.path_authority_current = false;
  entry.path_authority_authorized = false;
  if (state.path_authority != nullptr) {
    const auto observation = state.path_authority->observe(entry.record.path);
    if (observation.has_value()) {
      entry.path_authority_authorized = observation->authorized;
      entry.path_authority_current =
          observation->authorized && (observation->generation == entry.record.path_authority);
    }
  }
}

struct TargetApplication {
  std::uint32_t added = 0;
  std::uint32_t removed = 0;
};

// Validates a desired declared member set against the current group: structural
// well-formedness, path stability for already declared members, upstream
// bindings and cost-class compatibility.
std::optional<MutationResult> validate_target_set(const GovernorState& state,
                                                  const GroupState& group,
                                                  const std::vector<MemberSpec>& specs) {
  for (std::size_t left = 0; left < specs.size(); ++left) {
    if (!specs[left].is_well_formed()) {
      return reject(Outcome::MALFORMED_REQUEST, ConditionCode::MALFORMED_IDENTITY,
                    specs[left].member.to_text());
    }
    for (std::size_t right = left + 1; right < specs.size(); ++right) {
      if (specs[left].member == specs[right].member) {
        return reject(Outcome::DUPLICATE_MEMBER, ConditionCode::MEMBER_DUPLICATE,
                      specs[left].member.to_text());
      }
    }
  }
  if (specs.size() > state.limits.max_members_per_group) {
    return reject(Outcome::RESOURCE_LIMIT, ConditionCode::MEMBER_SET_LIMIT, "members",
                  specs.size(), state.limits.max_members_per_group);
  }
  if (specs.size() > group.bucket_count.value()) {
    return reject(Outcome::RESOURCE_LIMIT, ConditionCode::BUCKET_LIMIT, "members", specs.size(),
                  group.bucket_count.value());
  }
  for (const MemberSpec& spec : specs) {
    const MemberEntry* existing = group.find_member(spec.member);
    if (existing != nullptr && existing->record.declared && !(existing->record.path == spec.path)) {
      return reject(Outcome::MALFORMED_REQUEST, ConditionCode::MALFORMED_PAYLOAD,
                    spec.member.to_text());
    }
    const auto invalid =
        validate_spec(state, spec, group.cost_semantics, group.canonical_cost, group.source,
                      group.multipath_set, group.multipath_generation);
    if (invalid.has_value()) {
      return invalid;
    }
  }
  return std::nullopt;
}

std::uint32_t count_target_changes(const GovernorState& state, const GroupState& group,
                                   const std::vector<MemberSpec>& specs) {
  (void)state;
  std::uint32_t changes = 0;
  for (const MemberSpec& spec : specs) {
    const MemberEntry* existing = group.find_member(spec.member);
    if (existing == nullptr || !existing->record.declared) {
      ++changes;
      continue;
    }
    if (existing->record.administratively_enabled != spec.administratively_enabled ||
        !(existing->record.path_authority == spec.path_authority) ||
        !(existing->record.member_generation == spec.member_generation) ||
        !(existing->record.cost == spec.cost)) {
      ++changes;
    }
  }
  for (const MemberEntry& entry : group.members) {
    if (!entry.record.declared) {
      continue;
    }
    const bool present =
        std::any_of(specs.begin(), specs.end(),
                    [&entry](const MemberSpec& spec) { return spec.member == entry.record.member; });
    if (!present) {
      ++changes;
    }
  }
  return changes;
}

TargetApplication apply_target_set(GroupState& group, const std::vector<MemberSpec>& specs) {
  TargetApplication application;
  for (MemberEntry& entry : group.members) {
    if (!entry.record.declared) {
      continue;
    }
    const bool present =
        std::any_of(specs.begin(), specs.end(),
                    [&entry](const MemberSpec& spec) { return spec.member == entry.record.member; });
    if (!present) {
      entry.record.declared = false;
      entry.record.administratively_enabled = true;
      ++application.removed;
    }
  }
  for (const MemberSpec& spec : specs) {
    MemberEntry* entry = group.find_member(spec.member);
    if (entry == nullptr) {
      MemberEntry fresh;
      fresh.record = detail::make_record(spec, spec.administratively_enabled);
      fresh.path_authority_current = true;
      fresh.path_authority_authorized = true;
      fresh.multipath_current = true;
      fresh.cost_current = true;
      group.members.push_back(std::move(fresh));
      ++application.added;
      continue;
    }
    if (!entry->record.declared) {
      ++application.added;
    }
    entry->record = detail::make_record(spec, spec.administratively_enabled);
    entry->path_authority_current = true;
    entry->path_authority_authorized = true;
    entry->multipath_current = true;
    entry->cost_current = true;
  }
  sort_members(group.members);
  return application;
}

std::vector<MemberSpec> canonical_specs(const std::vector<MemberSpec>& specs) {
  std::vector<MemberSpec> sorted = specs;
  std::stable_sort(sorted.begin(), sorted.end(),
                   [](const MemberSpec& left, const MemberSpec& right) {
                     return std::tie(left.path, left.member) < std::tie(right.path, right.member);
                   });
  return sorted;
}

RebalancePlanId derive_plan_id(const ECMPGroupId& group, MembershipGeneration from_membership,
                               AssignmentGeneration from_assignment, const Digest& target_digest) {
  Encoder encoder;
  encoder.raw(group.bytes());
  encoder.u64(from_membership.value());
  encoder.u64(from_assignment.value());
  encoder.raw(target_digest.bytes());
  const Digest digest = domain_digest("ecmp.rebalance-plan.v1", encoder.bytes());
  std::array<std::uint8_t, 16> raw{};
  std::copy(digest.bytes().begin(), digest.bytes().begin() + 16, raw.begin());
  return RebalancePlanId::from_bytes(raw);
}

}  // namespace

MutationResult EcmpGovernor::revalidate_group(const RevalidateGroupRequest& request) {
  std::unique_lock lock(state_->mutex);
  GovernorState& state = *state_;
  const Digest payload = domain_digest(kAttemptDomain, encode_payload(request));
  GroupPreamble preamble;
  if (!group_preamble(state, request.authority, request.group, Capability::MUTATE_GROUP, payload,
                      GroupEvent::REVALIDATE, preamble)) {
    return preamble.result;
  }
  GroupState& group = *preamble.group;

  if (request.members.size() > state.limits.max_batch_size) {
    return reject(Outcome::RESOURCE_LIMIT, ConditionCode::BATCH_LIMIT, "members",
                  request.members.size(), state.limits.max_batch_size);
  }
  for (std::size_t left = 0; left < request.members.size(); ++left) {
    for (std::size_t right = left + 1; right < request.members.size(); ++right) {
      if (request.members[left].member == request.members[right].member) {
        return reject(Outcome::MALFORMED_REQUEST, ConditionCode::MALFORMED_PAYLOAD,
                      request.members[left].member.to_text());
      }
    }
  }

  // Cost-policy adoption.  A group may only move to a new cost policy generation
  // when every declared member is re-proved under one single compatible binding
  // and that generation is the generation the cost authority currently reports.
  std::vector<const MemberRevalidation*> claim_updates;
  for (const MemberRevalidation& update : request.members) {
    if (update.cost.has_value()) {
      claim_updates.push_back(&update);
    }
  }
  bool adoption_needed = false;
  for (const MemberRevalidation* update : claim_updates) {
    if (update->cost->binding.policy_generation !=
        group.cost_semantics.binding.policy_generation) {
      adoption_needed = true;
    }
  }
  if (adoption_needed) {
    if (claim_updates.size() != group.declared_count()) {
      return reject(Outcome::STALE_COST_GENERATION, ConditionCode::COST_POLICY_STALE, "members",
                    claim_updates.size(), group.declared_count());
    }
    const CostClaim& reference = *claim_updates.front()->cost;
    for (const MemberRevalidation* update : claim_updates) {
      if (update->cost->cost_class != group.cost_semantics.cost_class ||
          !(update->cost->binding == reference.binding) ||
          !(update->cost->cost == reference.cost)) {
        return reject(Outcome::COST_CLASS_MISMATCH, ConditionCode::COST_MODEL_MISMATCH,
                      update->member.to_text());
      }
    }
    const auto current = state.current_cost_policy.find(group.cost_semantics.cost_class);
    if (current == state.current_cost_policy.end() ||
        current->second != reference.binding.policy_generation) {
      return reject(Outcome::STALE_COST_GENERATION, ConditionCode::COST_POLICY_STALE,
                    reference.binding.policy_generation.value() == 0
                        ? std::string("policy")
                        : std::to_string(reference.binding.policy_generation.value()));
    }
    group.cost_semantics.binding = reference.binding;
    group.canonical_cost = reference.cost;
    group.currentness.remove(CurrentnessCause::STALE_COST_CLASS);
  }

  for (const MemberRevalidation& update : request.members) {
    MemberEntry* entry = group.find_member(update.member);
    if (entry == nullptr) {
      return reject(Outcome::UNKNOWN_MEMBER, ConditionCode::MEMBER_UNKNOWN,
                    update.member.to_text());
    }
    if (!entry->record.declared) {
      return reject(Outcome::UNKNOWN_MEMBER, ConditionCode::MEMBER_WITHDRAWN,
                    update.member.to_text());
    }
    MemberSpec spec = spec_of(entry->record);
    if (!update.path_authority.is_zero()) {
      spec.path_authority = update.path_authority;
    }
    if (update.cost.has_value()) {
      spec.cost = *update.cost;
    }
    const auto invalid =
        validate_spec(state, spec, group.cost_semantics, group.canonical_cost, group.source,
                      group.multipath_set, group.multipath_generation);
    if (invalid.has_value()) {
      return *invalid;
    }
    entry->record.path_authority = spec.path_authority;
    entry->record.cost = spec.cost;
  }

  if (request.multipath_generation.has_value()) {
    if (group.source != MembershipSource::MULTIPATH_FABRIC) {
      return reject(Outcome::MALFORMED_REQUEST, ConditionCode::MULTIPATH_SET_STALE,
                    "multipath_generation");
    }
    const auto current =
        state.multipath == nullptr ? std::nullopt : state.multipath->generation(group.multipath_set);
    if (!current.has_value() || !(*current == *request.multipath_generation)) {
      return reject(Outcome::STALE_MULTIPATH_SET, ConditionCode::MULTIPATH_SET_STALE, "generation",
                    current.has_value() ? current->value() : 0,
                    request.multipath_generation->value());
    }
    group.multipath_generation = *request.multipath_generation;
    group.currentness.remove(CurrentnessCause::STALE_MULTIPATH_SET);
  }

  // Explicit revalidation is what restores conservative currentness: the caller
  // has bound the current epoch, the current publisher authority, the current
  // path authority, the current multipath binding and the current cost policy.
  group.currentness.remove(CurrentnessCause::STALE_EPOCH);
  group.currentness.remove(CurrentnessCause::FENCED_PUBLISHER);
  group.currentness.remove(CurrentnessCause::REVALIDATION_REQUIRED);
  group.currentness.remove(CurrentnessCause::STALE_COST_CLASS);
  for (MemberEntry& entry : group.members) {
    entry.cost_current = true;
  }
  reobserve_group(state, group);

  RefreshContext context =
      make_context(state, request.authority, ChangeReason::REVALIDATION, GroupEvent::REVALIDATE);
  return finish_group_mutation(state, group, preamble.declared_before, context, request.authority,
                               payload, Outcome::REVALIDATED);
}

MutationResult EcmpGovernor::plan_rebalance(const RebalancePlanRequest& request) {
  std::unique_lock lock(state_->mutex);
  GovernorState& state = *state_;
  const Digest payload = domain_digest(kAttemptDomain, encode_payload(request));
  GroupPreamble preamble;
  if (!group_preamble(state, request.authority, request.group, Capability::MUTATE_GROUP, payload,
                      GroupEvent::PLAN_REBALANCE, preamble)) {
    return preamble.result;
  }
  GroupState& group = *preamble.group;
  if (group.plan.has_value()) {
    return reject(Outcome::LIFECYCLE_VIOLATION, ConditionCode::PLAN_STALE, "plan_pending");
  }
  const auto invalid = validate_target_set(state, group, request.target_members);
  if (invalid.has_value()) {
    return *invalid;
  }
  const std::uint32_t changes = count_target_changes(state, group, request.target_members);
  if (changes > state.limits.max_batch_size) {
    return reject(Outcome::RESOURCE_LIMIT, ConditionCode::BATCH_LIMIT, "changes", changes,
                  state.limits.max_batch_size);
  }

  const std::uint64_t committed_before = state.committed_rebalances;
  GroupState trial = group;
  const TargetApplication application = apply_target_set(trial, request.target_members);
  RefreshContext trial_context = make_context(
      state, request.authority,
      application.added > 0 ? ChangeReason::ADD_MEMBER : ChangeReason::REMOVE_MEMBER,
      application.added > 0 ? GroupEvent::ADD_MEMBER : GroupEvent::REMOVE_MEMBER);
  ConditionList conditions(state.limits.max_explanation_entries);
  const auto failure = detail::refresh_group(state, trial, trial_context, conditions);
  if (failure.has_value()) {
    state.committed_rebalances = committed_before;
    MutationResult result;
    result.outcome = *failure;
    result.conditions = conditions;
    return result;
  }
  const std::uint64_t churn = trial.last_rebalance.has_value() ? trial.last_rebalance->churn : 0;
  if (trial.assignment_generation != group.assignment_generation &&
      churn > state.limits.max_rebalance_moves) {
    state.committed_rebalances = committed_before;
    return reject(Outcome::RESOURCE_LIMIT, ConditionCode::CHURN_LIMIT, "churn", churn,
                  state.limits.max_rebalance_moves);
  }
  state.committed_rebalances = committed_before;

  detail::PlanEntry plan;
  plan.from_membership = group.membership_generation;
  plan.from_assignment = group.assignment_generation;
  plan.from_authority = group.authority_generation;
  plan.target_membership = trial.membership_generation;
  plan.target_membership_digest = detail::compute_declared_digest(trial);
  plan.target_members = canonical_specs(request.target_members);
  if (trial.assignment_generation != group.assignment_generation && trial.last_rebalance.has_value()) {
    plan.moves = trial.last_rebalance->moves;
  }
  plan.assignment = trial.assignment;
  plan.assignment_digest = trial.assignment.digest();
  plan.epoch = state.epoch;
  plan.publisher = request.authority.publisher;
  plan.plan = derive_plan_id(group.id, plan.from_membership, plan.from_assignment,
                             plan.target_membership_digest);
  group.plan = std::move(plan);

  RefreshContext context = make_context(state, request.authority, ChangeReason::REVALIDATION,
                                        GroupEvent::PLAN_REBALANCE);
  MutationResult result =
      finish_group_mutation(state, group, preamble.declared_before, context, request.authority,
                            payload, Outcome::REBALANCE_PLANNED);
  if (result.accepted() && result.group.has_value()) {
    result.plan = group.plan.has_value() ? std::optional<RebalancePlanId>(group.plan->plan)
                                         : std::nullopt;
  }
  return result;
}

MutationResult EcmpGovernor::commit_rebalance(const RebalanceCommitRequest& request) {
  std::unique_lock lock(state_->mutex);
  GovernorState& state = *state_;
  const Digest payload = domain_digest(kAttemptDomain, encode_payload(request));
  GroupPreamble preamble;
  if (!group_preamble(state, request.authority, request.group, Capability::MUTATE_GROUP, payload,
                      GroupEvent::COMMIT_REBALANCE, preamble)) {
    return preamble.result;
  }
  GroupState& group = *preamble.group;
  if (!group.plan.has_value()) {
    return reject(Outcome::NO_PENDING_PLAN, ConditionCode::PLAN_MISSING, "plan");
  }
  if (!(request.plan == group.plan->plan)) {
    return reject(Outcome::NO_PENDING_PLAN, ConditionCode::PLAN_MISSING, request.plan.to_text());
  }
  if (!(group.plan->from_membership == group.membership_generation)) {
    return reject(Outcome::STALE_PLAN, ConditionCode::PLAN_STALE, "membership_generation",
                  group.membership_generation.value(), group.plan->from_membership.value());
  }
  if (!(group.plan->from_assignment == group.assignment_generation)) {
    return reject(Outcome::STALE_PLAN, ConditionCode::PLAN_STALE, "assignment_generation",
                  group.assignment_generation.value(), group.plan->from_assignment.value());
  }
  if (!(group.plan->from_authority == group.authority_generation)) {
    return reject(Outcome::STALE_PLAN, ConditionCode::PLAN_STALE, "authority_generation",
                  group.authority_generation.value(), group.plan->from_authority.value());
  }

  const std::vector<MemberSpec> target = group.plan->target_members;
  const Digest predicted = group.plan->assignment_digest;
  group.plan.reset();
  apply_target_set(group, target);

  RefreshContext context = make_context(state, request.authority, ChangeReason::REBALANCE_COMMIT,
                                        GroupEvent::COMMIT_REBALANCE);
  MutationResult result =
      finish_group_mutation(state, group, preamble.declared_before, context, request.authority,
                            payload, Outcome::REBALANCED);
  if (!result.accepted()) {
    return result;
  }
  if (!(group.assignment.digest() == predicted)) {
    return reject(Outcome::INTERNAL_ERROR, ConditionCode::INTERNAL_INVARIANT, "assignment_digest");
  }
  return result;
}

MutationResult EcmpGovernor::abort_rebalance(const RebalanceAbortRequest& request) {
  std::unique_lock lock(state_->mutex);
  GovernorState& state = *state_;
  const Digest payload = domain_digest(kAttemptDomain, encode_payload(request));
  GroupPreamble preamble;
  if (!group_preamble(state, request.authority, request.group, Capability::MUTATE_GROUP, payload,
                      GroupEvent::ABORT_REBALANCE, preamble)) {
    return preamble.result;
  }
  GroupState& group = *preamble.group;
  if (!group.plan.has_value()) {
    return reject(Outcome::NO_PENDING_PLAN, ConditionCode::PLAN_MISSING, "plan");
  }
  if (!(request.plan == group.plan->plan)) {
    return reject(Outcome::NO_PENDING_PLAN, ConditionCode::PLAN_MISSING, request.plan.to_text());
  }
  group.plan.reset();
  RefreshContext context = make_context(state, request.authority, ChangeReason::PLAN_ABORTED,
                                        GroupEvent::ABORT_REBALANCE);
  return finish_group_mutation(state, group, preamble.declared_before, context, request.authority,
                               payload, Outcome::REBALANCE_ABORTED);
}

MutationResult EcmpGovernor::withdraw_group(const GroupAdminRequest& request) {
  std::unique_lock lock(state_->mutex);
  GovernorState& state = *state_;
  const Digest payload = domain_digest(kAttemptDomain, encode_payload(request));
  const bool completing = state.find_group(request.group) != nullptr &&
                          state.find_group(request.group)->lifecycle ==
                              GroupLifecycle::WITHDRAWING;
  const GroupEvent event =
      completing ? GroupEvent::COMPLETE_WITHDRAW : GroupEvent::WITHDRAW;
  GroupPreamble preamble;
  if (!group_preamble(state, request.authority, request.group, Capability::MUTATE_GROUP, payload,
                      event, preamble)) {
    return preamble.result;
  }
  GroupState& group = *preamble.group;
  if (completing) {
    for (MemberEntry& entry : group.members) {
      entry.record.declared = false;
      entry.record.administratively_enabled = true;
    }
    group.currentness.add(CurrentnessCause::RETIRED);
  }
  RefreshContext context =
      make_context(state, request.authority, ChangeReason::ADMIN_WITHDRAW, event);
  return finish_group_mutation(state, group, preamble.declared_before, context, request.authority,
                               payload, Outcome::WITHDRAWN_OK);
}

MutationResult EcmpGovernor::revoke_group(const GroupAdminRequest& request) {
  std::unique_lock lock(state_->mutex);
  GovernorState& state = *state_;
  const Digest payload = domain_digest(kAttemptDomain, encode_payload(request));
  GroupPreamble preamble;
  if (!group_preamble(state, request.authority, request.group, Capability::MUTATE_GROUP, payload,
                      GroupEvent::REVOKE, preamble)) {
    return preamble.result;
  }
  GroupState& group = *preamble.group;
  for (MemberEntry& entry : group.members) {
    entry.record.administratively_enabled = false;
  }
  group.currentness.add(CurrentnessCause::RETIRED);
  RefreshContext context =
      make_context(state, request.authority, ChangeReason::ADMIN_REVOKE, GroupEvent::REVOKE);
  return finish_group_mutation(state, group, preamble.declared_before, context, request.authority,
                               payload, Outcome::REVOKED_OK);
}

MutationResult EcmpGovernor::retire_group(const GroupAdminRequest& request) {
  std::unique_lock lock(state_->mutex);
  GovernorState& state = *state_;
  const Digest payload = domain_digest(kAttemptDomain, encode_payload(request));
  GroupPreamble preamble;
  if (!group_preamble(state, request.authority, request.group, Capability::MUTATE_GROUP, payload,
                      GroupEvent::RETIRE, preamble)) {
    return preamble.result;
  }
  GroupState& group = *preamble.group;
  for (MemberEntry& entry : group.members) {
    entry.record.declared = false;
    entry.record.administratively_enabled = false;
  }
  group.plan.reset();
  group.currentness.add(CurrentnessCause::RETIRED);
  RefreshContext context =
      make_context(state, request.authority, ChangeReason::ADMIN_WITHDRAW, GroupEvent::RETIRE);
  return finish_group_mutation(state, group, preamble.declared_before, context, request.authority,
                               payload, Outcome::RETIRED_OK);
}

MutationResult EcmpGovernor::supersede_group(const GroupAdminRequest& request) {
  std::unique_lock lock(state_->mutex);
  GovernorState& state = *state_;
  const Digest payload = domain_digest(kAttemptDomain, encode_payload(request));
  GroupPreamble preamble;
  if (!group_preamble(state, request.authority, request.group, Capability::MUTATE_GROUP, payload,
                      GroupEvent::SUPERSEDE, preamble)) {
    return preamble.result;
  }
  GroupState& group = *preamble.group;
  if (request.successor.is_nil() || request.successor == group.id) {
    return reject(Outcome::MALFORMED_REQUEST, ConditionCode::MALFORMED_IDENTITY, "successor");
  }
  GroupState* successor = state.find_group(request.successor);
  if (successor == nullptr) {
    return reject(Outcome::UNKNOWN_GROUP, ConditionCode::GROUP_UNKNOWN,
                  request.successor.to_text());
  }
  if (is_administratively_closed(successor->lifecycle) || successor->lifecycle ==
                                                              GroupLifecycle::RETIRED) {
    return reject(lifecycle_outcome(successor->lifecycle), ConditionCode::LIFECYCLE_DENIED,
                  request.successor.to_text());
  }
  group.successor = request.successor;
  successor->predecessor = group.id;
  for (MemberEntry& entry : group.members) {
    entry.record.administratively_enabled = false;
  }
  group.plan.reset();
  group.currentness.add(CurrentnessCause::RETIRED);
  RefreshContext context = make_context(state, request.authority, ChangeReason::SUPERSESSION,
                                        GroupEvent::SUPERSEDE);
  return finish_group_mutation(state, group, preamble.declared_before, context, request.authority,
                               payload, Outcome::SUPERSEDED_OK);
}

MutationResult EcmpGovernor::notify_path_authority_change(const PathAuthorityChangeNotice& notice) {
  std::unique_lock lock(state_->mutex);
  GovernorState& state = *state_;
  MutationResult result;
  if (!authorize_upstream(state, notice.epoch, notice.publisher, notice.worker_boot, result)) {
    return result;
  }
  if (notice.path.is_nil()) {
    return reject(Outcome::MALFORMED_REQUEST, ConditionCode::MALFORMED_IDENTITY, "path");
  }
  const auto found = state.path_index.find(notice.path);
  if (found == state.path_index.end()) {
    result.outcome = Outcome::NO_CHANGE;
    result.detail = "no dependent group";
    return result;
  }
  // Copy the dependent set: the loop mutates group state, and indexes are
  // rebuilt per group.
  const std::set<ECMPGroupId> dependents = found->second;
  const AuthorityScope& scope = scope_of(state, notice.publisher);
  std::uint32_t affected = 0;
  ConditionList conditions(state.limits.max_explanation_entries);
  for (const ECMPGroupId& id : dependents) {
    const auto group_it = state.groups.find(id);
    if (group_it == state.groups.end()) {
      continue;
    }
    GroupState& group = group_it->second;
    if (!scope.covers(group.key, group.id)) {
      conditions.add(make_condition(ConditionCode::SCOPE_DENIED, group.id.to_text()));
      continue;
    }
    if (is_administratively_closed(group.lifecycle)) {
      continue;
    }
    bool changed = false;
    for (MemberEntry& entry : group.members) {
      if (!entry.record.declared || !(entry.record.path == notice.path)) {
        continue;
      }
      const bool before = entry.path_authority_current;
      reobserve_member_path(state, entry);
      if (before != entry.path_authority_current) {
        changed = true;
      }
    }
    bool any_stale = false;
    for (const MemberEntry& entry : group.members) {
      if (entry.record.declared && !entry.path_authority_current) {
        any_stale = true;
        break;
      }
    }
    if (any_stale != group.currentness.has(CurrentnessCause::STALE_PATH_AUTHORITY)) {
      if (any_stale) {
        group.currentness.add(CurrentnessCause::STALE_PATH_AUTHORITY);
      } else {
        group.currentness.remove(CurrentnessCause::STALE_PATH_AUTHORITY);
      }
      changed = true;
    }
    if (!changed) {
      continue;
    }
    RefreshContext context;
    context.reason = ChangeReason::PATH_INVALIDATION;
    context.event = GroupEvent::INVALIDATE_PATH;
    context.publisher = notice.publisher;
    context.worker_boot = notice.worker_boot;
    context.epoch = state.epoch;
    context.bind_authority = false;
    const auto failure = detail::refresh_group(state, group, context, conditions);
    if (failure.has_value()) {
      result.outcome = *failure;
      result.conditions = conditions;
      return result;
    }
    state.index_group_paths(group);
    ++affected;
  }
  result.outcome = affected > 0 ? Outcome::REBALANCED : Outcome::NO_CHANGE;
  result.conditions = conditions;
  result.detail = "affected_groups=" + std::to_string(affected);
  return result;
}

MutationResult EcmpGovernor::notify_multipath_set_change(const MultipathSetChangeNotice& notice) {
  std::unique_lock lock(state_->mutex);
  GovernorState& state = *state_;
  MutationResult result;
  if (!authorize_upstream(state, notice.epoch, notice.publisher, notice.worker_boot, result)) {
    return result;
  }
  if (notice.set.is_nil()) {
    return reject(Outcome::MALFORMED_REQUEST, ConditionCode::MALFORMED_IDENTITY, "multipath_set");
  }
  const auto found = state.multipath_index.find(notice.set);
  if (found == state.multipath_index.end()) {
    result.outcome = Outcome::NO_CHANGE;
    result.detail = "no dependent group";
    return result;
  }
  const std::set<ECMPGroupId> dependents = found->second;
  const AuthorityScope& scope = scope_of(state, notice.publisher);
  std::uint32_t affected = 0;
  ConditionList conditions(state.limits.max_explanation_entries);
  for (const ECMPGroupId& id : dependents) {
    const auto group_it = state.groups.find(id);
    if (group_it == state.groups.end()) {
      continue;
    }
    GroupState& group = group_it->second;
    if (!scope.covers(group.key, group.id)) {
      conditions.add(make_condition(ConditionCode::SCOPE_DENIED, group.id.to_text()));
      continue;
    }
    if (group.source != MembershipSource::MULTIPATH_FABRIC ||
        is_administratively_closed(group.lifecycle)) {
      continue;
    }
    bool stale = true;
    if (state.multipath != nullptr) {
      const auto current = state.multipath->generation(group.multipath_set);
      if (current.has_value() && (*current == group.multipath_generation)) {
        stale = false;
        for (const MemberEntry& entry : group.members) {
          if (entry.record.declared &&
              !state.multipath->contains(group.multipath_set, group.multipath_generation,
                                         entry.record.path)) {
            stale = true;
            break;
          }
        }
      }
    }
    const bool had = group.currentness.has(CurrentnessCause::STALE_MULTIPATH_SET);
    if (stale == had) {
      continue;
    }
    if (stale) {
      group.currentness.add(CurrentnessCause::STALE_MULTIPATH_SET);
      for (MemberEntry& entry : group.members) {
        if (entry.record.declared) {
          entry.multipath_current = false;
        }
      }
    } else {
      group.currentness.remove(CurrentnessCause::STALE_MULTIPATH_SET);
      for (MemberEntry& entry : group.members) {
        entry.multipath_current = true;
      }
    }
    RefreshContext context;
    context.reason = ChangeReason::MULTIPATH_INVALIDATION;
    context.event = GroupEvent::INVALIDATE_MULTIPATH;
    context.publisher = notice.publisher;
    context.worker_boot = notice.worker_boot;
    context.epoch = state.epoch;
    context.bind_authority = false;
    const auto failure = detail::refresh_group(state, group, context, conditions);
    if (failure.has_value()) {
      result.outcome = *failure;
      result.conditions = conditions;
      return result;
    }
    ++affected;
  }
  result.outcome = affected > 0 ? Outcome::REBALANCED : Outcome::NO_CHANGE;
  result.conditions = conditions;
  result.detail = "affected_groups=" + std::to_string(affected);
  return result;
}

MutationResult EcmpGovernor::notify_cost_generation_change(
    const CostGenerationChangeNotice& notice) {
  std::unique_lock lock(state_->mutex);
  GovernorState& state = *state_;
  MutationResult result;
  if (!authorize_upstream(state, notice.epoch, notice.publisher, notice.worker_boot, result)) {
    return result;
  }
  if (notice.cost_class.is_nil()) {
    return reject(Outcome::MALFORMED_REQUEST, ConditionCode::MALFORMED_IDENTITY, "cost_class");
  }
  state.current_cost_policy[notice.cost_class] = notice.generation;

  const auto found = state.cost_class_index.find(notice.cost_class);
  if (found == state.cost_class_index.end()) {
    result.outcome = Outcome::NO_CHANGE;
    result.detail = "no dependent group";
    return result;
  }
  const std::set<ECMPGroupId> dependents = found->second;
  const AuthorityScope& scope = scope_of(state, notice.publisher);
  std::uint32_t affected = 0;
  ConditionList conditions(state.limits.max_explanation_entries);
  for (const ECMPGroupId& id : dependents) {
    const auto group_it = state.groups.find(id);
    if (group_it == state.groups.end()) {
      continue;
    }
    GroupState& group = group_it->second;
    if (!scope.covers(group.key, group.id)) {
      conditions.add(make_condition(ConditionCode::SCOPE_DENIED, group.id.to_text()));
      continue;
    }
    if (is_administratively_closed(group.lifecycle)) {
      continue;
    }
    const bool stale = !(group.cost_semantics.binding.policy_generation == notice.generation);
    const bool had = group.currentness.has(CurrentnessCause::STALE_COST_CLASS);
    if (stale == had) {
      continue;
    }
    if (stale) {
      group.currentness.add(CurrentnessCause::STALE_COST_CLASS);
      for (MemberEntry& entry : group.members) {
        if (entry.record.declared) {
          entry.cost_current = false;
        }
      }
    } else {
      group.currentness.remove(CurrentnessCause::STALE_COST_CLASS);
      for (MemberEntry& entry : group.members) {
        entry.cost_current = true;
      }
    }
    RefreshContext context;
    context.reason = ChangeReason::COST_INVALIDATION;
    context.event = GroupEvent::INVALIDATE_COST;
    context.publisher = notice.publisher;
    context.worker_boot = notice.worker_boot;
    context.epoch = state.epoch;
    context.bind_authority = false;
    const auto failure = detail::refresh_group(state, group, context, conditions);
    if (failure.has_value()) {
      result.outcome = *failure;
      result.conditions = conditions;
      return result;
    }
    ++affected;
  }
  result.outcome = affected > 0 ? Outcome::REBALANCED : Outcome::NO_CHANGE;
  result.conditions = conditions;
  result.detail = "affected_groups=" + std::to_string(affected);
  return result;
}

}  // namespace ecmp
