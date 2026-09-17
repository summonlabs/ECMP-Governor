#include "ecmp/lifecycle.hpp"

#include <string>

namespace ecmp {
namespace {

constexpr std::uint32_t event_bit(GroupEvent event) noexcept {
  return 1u << (static_cast<std::uint32_t>(event) - 1u);
}

constexpr std::uint32_t kMemberEvents = event_bit(GroupEvent::ADD_MEMBER) |
                                        event_bit(GroupEvent::REMOVE_MEMBER) |
                                        event_bit(GroupEvent::DISABLE_MEMBER) |
                                        event_bit(GroupEvent::ENABLE_MEMBER);

constexpr std::uint32_t kInvalidations =
    event_bit(GroupEvent::INVALIDATE_PATH) | event_bit(GroupEvent::INVALIDATE_MULTIPATH) |
    event_bit(GroupEvent::INVALIDATE_COST) | event_bit(GroupEvent::INVALIDATE_EPOCH);

constexpr std::uint32_t kRevalidate = event_bit(GroupEvent::REVALIDATE);
constexpr std::uint32_t kPlan = event_bit(GroupEvent::PLAN_REBALANCE);
constexpr std::uint32_t kCommit = event_bit(GroupEvent::COMMIT_REBALANCE);
constexpr std::uint32_t kAbort = event_bit(GroupEvent::ABORT_REBALANCE);
constexpr std::uint32_t kWithdraw = event_bit(GroupEvent::WITHDRAW);
constexpr std::uint32_t kCompleteWithdraw = event_bit(GroupEvent::COMPLETE_WITHDRAW);
constexpr std::uint32_t kRevoke = event_bit(GroupEvent::REVOKE);
constexpr std::uint32_t kSupersede = event_bit(GroupEvent::SUPERSEDE);
constexpr std::uint32_t kRetire = event_bit(GroupEvent::RETIRE);

constexpr std::uint32_t kOrdinaryEvents = kMemberEvents | kInvalidations | kRevalidate;

constexpr std::uint32_t member_event_bit(MemberEvent event) noexcept {
  return 1u << (static_cast<std::uint32_t>(event) - 1u);
}

constexpr std::uint32_t kMemberStale = member_event_bit(MemberEvent::UPSTREAM_STALE) |
                                       member_event_bit(MemberEvent::COST_STALE);
constexpr std::uint32_t kMemberWithdraw = member_event_bit(MemberEvent::WITHDRAW);
constexpr std::uint32_t kMemberRetire = member_event_bit(MemberEvent::RETIRE);

}  // namespace

std::string_view to_string(MembershipSource source) noexcept {
  switch (source) {
    case MembershipSource::DIRECT_PATH_SET: return "DIRECT_PATH_SET";
    case MembershipSource::MULTIPATH_FABRIC: return "MULTIPATH_FABRIC";
  }
  return "UNKNOWN_MEMBERSHIP_SOURCE";
}

std::string_view to_string(GroupLifecycle lifecycle) noexcept {
  switch (lifecycle) {
    case GroupLifecycle::DECLARED: return "DECLARED";
    case GroupLifecycle::ACTIVE: return "ACTIVE";
    case GroupLifecycle::DEGRADED: return "DEGRADED";
    case GroupLifecycle::REVALIDATION_REQUIRED: return "REVALIDATION_REQUIRED";
    case GroupLifecycle::REBALANCING: return "REBALANCING";
    case GroupLifecycle::WITHDRAWING: return "WITHDRAWING";
    case GroupLifecycle::WITHDRAWN: return "WITHDRAWN";
    case GroupLifecycle::REVOKED: return "REVOKED";
    case GroupLifecycle::SUPERSEDED: return "SUPERSEDED";
    case GroupLifecycle::RETIRED: return "RETIRED";
  }
  return "UNKNOWN_GROUP_LIFECYCLE";
}

bool is_terminal_lifecycle(GroupLifecycle lifecycle) noexcept {
  switch (lifecycle) {
    case GroupLifecycle::WITHDRAWN:
    case GroupLifecycle::REVOKED:
    case GroupLifecycle::SUPERSEDED:
    case GroupLifecycle::RETIRED:
      return true;
    default:
      return false;
  }
}

bool is_administratively_closed(GroupLifecycle lifecycle) noexcept {
  switch (lifecycle) {
    case GroupLifecycle::WITHDRAWING:
    case GroupLifecycle::WITHDRAWN:
    case GroupLifecycle::REVOKED:
    case GroupLifecycle::SUPERSEDED:
    case GroupLifecycle::RETIRED:
      return true;
    default:
      return false;
  }
}

std::string_view to_string(GroupEvent event) noexcept {
  switch (event) {
    case GroupEvent::CREATE: return "CREATE";
    case GroupEvent::ADD_MEMBER: return "ADD_MEMBER";
    case GroupEvent::REMOVE_MEMBER: return "REMOVE_MEMBER";
    case GroupEvent::DISABLE_MEMBER: return "DISABLE_MEMBER";
    case GroupEvent::ENABLE_MEMBER: return "ENABLE_MEMBER";
    case GroupEvent::INVALIDATE_PATH: return "INVALIDATE_PATH";
    case GroupEvent::INVALIDATE_MULTIPATH: return "INVALIDATE_MULTIPATH";
    case GroupEvent::INVALIDATE_COST: return "INVALIDATE_COST";
    case GroupEvent::INVALIDATE_EPOCH: return "INVALIDATE_EPOCH";
    case GroupEvent::REVALIDATE: return "REVALIDATE";
    case GroupEvent::PLAN_REBALANCE: return "PLAN_REBALANCE";
    case GroupEvent::COMMIT_REBALANCE: return "COMMIT_REBALANCE";
    case GroupEvent::ABORT_REBALANCE: return "ABORT_REBALANCE";
    case GroupEvent::WITHDRAW: return "WITHDRAW";
    case GroupEvent::COMPLETE_WITHDRAW: return "COMPLETE_WITHDRAW";
    case GroupEvent::REVOKE: return "REVOKE";
    case GroupEvent::SUPERSEDE: return "SUPERSEDE";
    case GroupEvent::RETIRE: return "RETIRE";
  }
  return "UNKNOWN_GROUP_EVENT";
}

GroupLifecycle derive_lifecycle(const LifecycleInputs& inputs) noexcept {
  if (inputs.plan_pending) {
    return GroupLifecycle::REBALANCING;
  }
  if (inputs.declared_members == 0) {
    return GroupLifecycle::DECLARED;
  }
  if (inputs.active_members == 0) {
    return GroupLifecycle::REVALIDATION_REQUIRED;
  }
  if (!inputs.authority_current) {
    return GroupLifecycle::REVALIDATION_REQUIRED;
  }
  if (inputs.active_members < inputs.min_active_members) {
    return GroupLifecycle::DEGRADED;
  }
  return GroupLifecycle::ACTIVE;
}

bool lifecycle_allows(GroupLifecycle state, GroupEvent event) noexcept {
  const std::uint32_t requested = event_bit(event);
  switch (state) {
    case GroupLifecycle::DECLARED:
      // No plan can exist before any member is bound.
      return (kOrdinaryEvents | kWithdraw | kRevoke | kSupersede | kRetire) & requested;
    case GroupLifecycle::ACTIVE:
    case GroupLifecycle::DEGRADED:
      return (kOrdinaryEvents | kPlan | kCommit | kAbort | kWithdraw | kRevoke | kSupersede |
              kRetire) &
             requested;
    case GroupLifecycle::REVALIDATION_REQUIRED:
      return (kOrdinaryEvents | kWithdraw | kRevoke | kSupersede | kRetire) & requested;
    case GroupLifecycle::REBALANCING:
      // Membership mutation is refused while a plan is pending: the pending plan
      // is bound to the membership generation it was computed from, and a
      // deterministic refusal is preferable to a silent stale completion.
      return (kInvalidations | kRevalidate | kCommit | kAbort | kWithdraw | kRevoke | kSupersede |
              kRetire) &
             requested;
    case GroupLifecycle::WITHDRAWING:
      return (kCompleteWithdraw | kRevoke | kRetire) & requested;
    case GroupLifecycle::WITHDRAWN:
      return (kRevoke | kSupersede | kRetire) & requested;
    case GroupLifecycle::REVOKED:
      return kRetire & requested;
    case GroupLifecycle::SUPERSEDED:
      return kRetire & requested;
    case GroupLifecycle::RETIRED:
      return false;
  }
  return false;
}

std::optional<GroupLifecycle> apply_group_event(GroupLifecycle state, GroupEvent event,
                                                const LifecycleInputs& inputs) noexcept {
  if (!lifecycle_allows(state, event)) {
    return std::nullopt;
  }
  switch (event) {
    case GroupEvent::CREATE:
      return GroupLifecycle::DECLARED;
    case GroupEvent::PLAN_REBALANCE:
      return GroupLifecycle::REBALANCING;
    case GroupEvent::WITHDRAW:
      return GroupLifecycle::WITHDRAWING;
    case GroupEvent::COMPLETE_WITHDRAW:
      return GroupLifecycle::WITHDRAWN;
    case GroupEvent::REVOKE:
      return GroupLifecycle::REVOKED;
    case GroupEvent::SUPERSEDE:
      return GroupLifecycle::SUPERSEDED;
    case GroupEvent::RETIRE:
      return GroupLifecycle::RETIRED;
    default:
      break;
  }
  // Every remaining event recomputes the derived lifecycle.  A recomputation can
  // never leave an administratively closed state because those transitions are
  // refused above.
  return derive_lifecycle(inputs);
}

std::string_view to_string(MemberState state) noexcept {
  switch (state) {
    case MemberState::ACTIVE: return "ACTIVE";
    case MemberState::REVALIDATION_REQUIRED: return "REVALIDATION_REQUIRED";
    case MemberState::INELIGIBLE: return "INELIGIBLE";
    case MemberState::WITHDRAWN: return "WITHDRAWN";
    case MemberState::RETIRED: return "RETIRED";
  }
  return "UNKNOWN_MEMBER_STATE";
}

std::string_view to_string(MemberEvent event) noexcept {
  switch (event) {
    case MemberEvent::DECLARE: return "DECLARE";
    case MemberEvent::UPSTREAM_STALE: return "UPSTREAM_STALE";
    case MemberEvent::UPSTREAM_RESTORED: return "UPSTREAM_RESTORED";
    case MemberEvent::COST_STALE: return "COST_STALE";
    case MemberEvent::DISABLE: return "DISABLE";
    case MemberEvent::ENABLE: return "ENABLE";
    case MemberEvent::WITHDRAW: return "WITHDRAW";
    case MemberEvent::RETIRE: return "RETIRE";
  }
  return "UNKNOWN_MEMBER_EVENT";
}

MemberState derive_member_state(const MemberInputs& inputs) noexcept {
  if (inputs.retired) {
    return MemberState::RETIRED;
  }
  if (!inputs.declared) {
    return MemberState::WITHDRAWN;
  }
  if (!inputs.upstream_current) {
    return MemberState::REVALIDATION_REQUIRED;
  }
  if (!inputs.administratively_enabled) {
    return MemberState::INELIGIBLE;
  }
  return MemberState::ACTIVE;
}

bool member_lifecycle_allows(MemberState state, MemberEvent event) noexcept {
  const std::uint32_t requested = member_event_bit(event);
  switch (state) {
    case MemberState::ACTIVE:
      return (kMemberStale | member_event_bit(MemberEvent::DISABLE) | kMemberWithdraw |
              kMemberRetire) &
             requested;
    case MemberState::REVALIDATION_REQUIRED:
      return (kMemberStale | member_event_bit(MemberEvent::UPSTREAM_RESTORED) |
              member_event_bit(MemberEvent::DISABLE) | kMemberWithdraw | kMemberRetire) &
             requested;
    case MemberState::INELIGIBLE:
      return (kMemberStale | member_event_bit(MemberEvent::ENABLE) | kMemberWithdraw |
              kMemberRetire) &
             requested;
    case MemberState::WITHDRAWN:
      return (member_event_bit(MemberEvent::DECLARE) | kMemberRetire) & requested;
    case MemberState::RETIRED:
      return false;
  }
  return false;
}

std::optional<MemberState> apply_member_event(MemberState state, MemberEvent event,
                                              const MemberInputs& inputs) noexcept {
  if (!member_lifecycle_allows(state, event)) {
    return std::nullopt;
  }
  return derive_member_state(inputs);
}

std::string_view to_string(CurrentnessCause cause) noexcept {
  switch (cause) {
    case CurrentnessCause::STALE_PATH_AUTHORITY: return "STALE_PATH_AUTHORITY";
    case CurrentnessCause::STALE_MULTIPATH_SET: return "STALE_MULTIPATH_SET";
    case CurrentnessCause::STALE_COST_CLASS: return "STALE_COST_CLASS";
    case CurrentnessCause::STALE_EPOCH: return "STALE_EPOCH";
    case CurrentnessCause::FENCED_PUBLISHER: return "FENCED_PUBLISHER";
    case CurrentnessCause::REVALIDATION_REQUIRED: return "REVALIDATION_REQUIRED";
    case CurrentnessCause::RETIRED: return "RETIRED";
  }
  return "UNKNOWN_CURRENTNESS_CAUSE";
}

void Currentness::add(CurrentnessCause cause) noexcept { bits_ |= mask_of(cause); }

void Currentness::remove(CurrentnessCause cause) noexcept { bits_ &= ~mask_of(cause); }

std::vector<CurrentnessCause> Currentness::causes() const {
  std::vector<CurrentnessCause> out;
  for (std::uint32_t index = 1; index <= kCurrentnessCauseCount; ++index) {
    const auto cause = static_cast<CurrentnessCause>(index);
    if (has(cause)) {
      out.push_back(cause);
    }
  }
  return out;
}

std::string Currentness::render() const {
  if (is_current()) {
    return "CURRENT";
  }
  std::string out;
  for (const CurrentnessCause cause : causes()) {
    if (!out.empty()) {
      out += '|';
    }
    out += to_string(cause);
  }
  return out;
}

bool Currentness::authority_current() const noexcept {
  return !(has(CurrentnessCause::STALE_EPOCH) || has(CurrentnessCause::FENCED_PUBLISHER) ||
           has(CurrentnessCause::REVALIDATION_REQUIRED) || has(CurrentnessCause::RETIRED));
}

std::string_view to_string(ChangeReason reason) noexcept {
  switch (reason) {
    case ChangeReason::CREATE: return "CREATE";
    case ChangeReason::ADD_MEMBER: return "ADD_MEMBER";
    case ChangeReason::REMOVE_MEMBER: return "REMOVE_MEMBER";
    case ChangeReason::DISABLE_MEMBER: return "DISABLE_MEMBER";
    case ChangeReason::ENABLE_MEMBER: return "ENABLE_MEMBER";
    case ChangeReason::PATH_INVALIDATION: return "PATH_INVALIDATION";
    case ChangeReason::MULTIPATH_INVALIDATION: return "MULTIPATH_INVALIDATION";
    case ChangeReason::COST_INVALIDATION: return "COST_INVALIDATION";
    case ChangeReason::EPOCH_INVALIDATION: return "EPOCH_INVALIDATION";
    case ChangeReason::REVALIDATION: return "REVALIDATION";
    case ChangeReason::ADMIN_WITHDRAW: return "ADMIN_WITHDRAW";
    case ChangeReason::ADMIN_REVOKE: return "ADMIN_REVOKE";
    case ChangeReason::SUPERSESSION: return "SUPERSESSION";
    case ChangeReason::RECOVERY: return "RECOVERY";
    case ChangeReason::PLAN_ABORTED: return "PLAN_ABORTED";
    case ChangeReason::REBALANCE_COMMIT: return "REBALANCE_COMMIT";
  }
  return "UNKNOWN_CHANGE_REASON";
}

}  // namespace ecmp
