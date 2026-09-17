#pragma once

#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ecmp {

// How ECMP membership is sourced.  The two modes have separate validation rules
// and are never conflated.
enum class MembershipSource : std::uint32_t {
  // Explicit exact path set supplied by the caller.  ECMP Governor validates
  // path authority and cost equality itself and claims no upstream
  // multipath-set governance.
  DIRECT_PATH_SET = 1,
  // Membership is bound to an exact governed multipath set and generation.  The
  // upstream set must still contain every member.
  MULTIPATH_FABRIC = 2,
};

[[nodiscard]] std::string_view to_string(MembershipSource source) noexcept;

// Group lifecycle.  This is the smallest model that keeps every real
// distinction: an administratively ended lineage (WITHDRAWN / REVOKED /
// SUPERSEDED / RETIRED) behaves differently from a group that merely lost its
// live authority (REVALIDATION_REQUIRED) or fell below its minimum
// (DEGRADED).
enum class GroupLifecycle : std::uint32_t {
  DECLARED = 1,
  ACTIVE = 2,
  DEGRADED = 3,
  REVALIDATION_REQUIRED = 4,
  REBALANCING = 5,
  WITHDRAWING = 6,
  WITHDRAWN = 7,
  REVOKED = 8,
  SUPERSEDED = 9,
  RETIRED = 10,
};

[[nodiscard]] std::string_view to_string(GroupLifecycle lifecycle) noexcept;

// True for lifecycles that no longer accept ordinary mutation.
[[nodiscard]] bool is_terminal_lifecycle(GroupLifecycle lifecycle) noexcept;

// True for lifecycles that are administrative end states which are never left.
[[nodiscard]] bool is_administratively_closed(GroupLifecycle lifecycle) noexcept;

enum class GroupEvent : std::uint32_t {
  CREATE = 1,
  ADD_MEMBER = 2,
  REMOVE_MEMBER = 3,
  DISABLE_MEMBER = 4,
  ENABLE_MEMBER = 5,
  INVALIDATE_PATH = 6,
  INVALIDATE_MULTIPATH = 7,
  INVALIDATE_COST = 8,
  INVALIDATE_EPOCH = 9,
  REVALIDATE = 10,
  PLAN_REBALANCE = 11,
  COMMIT_REBALANCE = 12,
  ABORT_REBALANCE = 13,
  WITHDRAW = 14,
  COMPLETE_WITHDRAW = 15,
  REVOKE = 16,
  SUPERSEDE = 17,
  RETIRE = 18,
};

inline constexpr std::uint32_t kGroupEventCount = 18;
inline constexpr std::uint32_t kGroupLifecycleCount = 10;

[[nodiscard]] std::string_view to_string(GroupEvent event) noexcept;

// Inputs of the derived (non sticky) lifecycle computation.  The result depends
// on nothing else: no timestamps, no arrival order, no process state.
struct LifecycleInputs {
  std::uint32_t declared_members = 0;
  std::uint32_t active_members = 0;
  std::uint32_t min_active_members = 1;
  bool plan_pending = false;
  bool authority_current = true;
};

// Derived lifecycle for a state that is not administratively ended.
[[nodiscard]] GroupLifecycle derive_lifecycle(const LifecycleInputs& inputs) noexcept;

// Static transition legality: is this event legal at all in this state?
[[nodiscard]] bool lifecycle_allows(GroupLifecycle state, GroupEvent event) noexcept;

// Full transition.  For administratively closing events the target is fixed; for
// every other event the target is recomputed from `inputs`, which the caller
// must supply as the post-event inputs.
[[nodiscard]] std::optional<GroupLifecycle> apply_group_event(GroupLifecycle state, GroupEvent event,
                                                              const LifecycleInputs& inputs) noexcept;

// Member lifecycle.  ELIGIBLE and ACTIVE are deliberately collapsed in 1.0.0:
// the governor enforces bucket_count >= maximum members per group, so an
// eligible member always owns at least one bucket and a separate eligible-only
// state would be unobservable.  PENDING is likewise unobservable because
// membership is validated synchronously and atomically at declaration.
enum class MemberState : std::uint32_t {
  ACTIVE = 1,
  REVALIDATION_REQUIRED = 2,
  INELIGIBLE = 3,
  WITHDRAWN = 4,
  RETIRED = 5,
};

[[nodiscard]] std::string_view to_string(MemberState state) noexcept;

enum class MemberEvent : std::uint32_t {
  DECLARE = 1,
  UPSTREAM_STALE = 2,
  UPSTREAM_RESTORED = 3,
  COST_STALE = 4,
  DISABLE = 5,
  ENABLE = 6,
  WITHDRAW = 7,
  RETIRE = 8,
};

inline constexpr std::uint32_t kMemberEventCount = 8;
inline constexpr std::uint32_t kMemberStateCount = 5;

[[nodiscard]] std::string_view to_string(MemberEvent event) noexcept;

struct MemberInputs {
  bool declared = true;
  bool administratively_enabled = true;
  bool upstream_current = true;
  bool retired = false;
};

[[nodiscard]] MemberState derive_member_state(const MemberInputs& inputs) noexcept;
[[nodiscard]] bool member_lifecycle_allows(MemberState state, MemberEvent event) noexcept;
[[nodiscard]] std::optional<MemberState> apply_member_event(MemberState state, MemberEvent event,
                                                            const MemberInputs& inputs) noexcept;

// Currentness causes are never collapsed into one "stale" flag: an operator must
// be able to tell a stale path authority from a fenced publisher.
enum class CurrentnessCause : std::uint32_t {
  STALE_PATH_AUTHORITY = 1,
  STALE_MULTIPATH_SET = 2,
  STALE_COST_CLASS = 3,
  STALE_EPOCH = 4,
  FENCED_PUBLISHER = 5,
  REVALIDATION_REQUIRED = 6,
  RETIRED = 7,
};

inline constexpr std::uint32_t kCurrentnessCauseCount = 7;

[[nodiscard]] std::string_view to_string(CurrentnessCause cause) noexcept;

class Currentness {
 public:
  constexpr Currentness() noexcept = default;

  [[nodiscard]] static constexpr Currentness from_bits(std::uint32_t bits) noexcept {
    Currentness value;
    value.bits_ = bits;
    return value;
  }
  [[nodiscard]] static constexpr Currentness current() noexcept { return Currentness{}; }

  void add(CurrentnessCause cause) noexcept;
  void remove(CurrentnessCause cause) noexcept;
  void clear() noexcept { bits_ = 0; }

  [[nodiscard]] constexpr bool is_current() const noexcept { return bits_ == 0; }
  [[nodiscard]] constexpr bool has(CurrentnessCause cause) const noexcept {
    return (bits_ & mask_of(cause)) != 0;
  }
  [[nodiscard]] constexpr std::uint32_t bits() const noexcept { return bits_; }
  [[nodiscard]] std::vector<CurrentnessCause> causes() const;
  [[nodiscard]] std::string render() const;

  // Authority is "group level current" when none of the causes that invalidate
  // the group's live authority are present.  Per-member staleness (a stale path
  // authority on one member, for example) does not by itself make the group
  // lose its live authority; it makes that member ineligible.
  [[nodiscard]] bool authority_current() const noexcept;

  friend constexpr bool operator==(const Currentness&, const Currentness&) noexcept = default;
  friend constexpr auto operator<=>(const Currentness&, const Currentness&) noexcept = default;

 private:
  [[nodiscard]] static constexpr std::uint32_t mask_of(CurrentnessCause cause) noexcept {
    return 1u << (static_cast<std::uint32_t>(cause) - 1u);
  }

  std::uint32_t bits_ = 0;
};

// Why a recorded change happened.  Bounded, stable, persisted.
enum class ChangeReason : std::uint32_t {
  CREATE = 1,
  ADD_MEMBER = 2,
  REMOVE_MEMBER = 3,
  DISABLE_MEMBER = 4,
  ENABLE_MEMBER = 5,
  PATH_INVALIDATION = 6,
  MULTIPATH_INVALIDATION = 7,
  COST_INVALIDATION = 8,
  EPOCH_INVALIDATION = 9,
  REVALIDATION = 10,
  ADMIN_WITHDRAW = 11,
  ADMIN_REVOKE = 12,
  SUPERSESSION = 13,
  RECOVERY = 14,
  PLAN_ABORTED = 15,
  REBALANCE_COMMIT = 16,
};

[[nodiscard]] std::string_view to_string(ChangeReason reason) noexcept;

}  // namespace ecmp
