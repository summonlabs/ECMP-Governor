#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace ecmp {

// Structured mutation outcome.  Numeric values are part of the wire contract and
// are never renumbered: new codes are appended.
enum class Outcome : std::uint32_t {
  CREATED = 1,
  MEMBER_ADDED = 2,
  MEMBER_REMOVED = 3,
  MEMBER_DISABLED = 4,
  MEMBER_ENABLED = 5,
  REBALANCED = 6,
  REBALANCE_PLANNED = 7,
  REBALANCE_ABORTED = 8,
  REVALIDATED = 9,
  WITHDRAWN_OK = 10,
  REVOKED_OK = 11,
  RETIRED_OK = 12,
  SUPERSEDED_OK = 13,
  NO_CHANGE = 14,
  IDEMPOTENT = 15,
  REGISTERED = 16,
  FENCED = 17,
  STALE_EPOCH = 20,
  STALE_WORKER = 21,
  UNAUTHORIZED = 22,
  UNKNOWN_GROUP = 23,
  UNKNOWN_MEMBER = 24,
  DUPLICATE_GROUP = 25,
  DUPLICATE_MEMBER = 26,
  STALE_GROUP_GENERATION = 27,
  STALE_ASSIGNMENT_GENERATION = 28,
  STALE_AUTHORITY_GENERATION = 29,
  STALE_PATH_AUTHORITY = 30,
  STALE_MULTIPATH_SET = 31,
  STALE_COST_GENERATION = 32,
  COST_MISMATCH = 33,
  COST_CLASS_MISMATCH = 34,
  INSUFFICIENT_MEMBERS = 35,
  RESOURCE_LIMIT = 36,
  REVALIDATION_REQUIRED = 37,
  LIFECYCLE_VIOLATION = 38,
  NO_PENDING_PLAN = 39,
  STALE_PLAN = 40,
  ATTEMPT_CONFLICT = 41,
  MALFORMED_REQUEST = 42,
  REVOKED = 43,
  RETIRED = 44,
  WITHDRAWN = 45,
  SUPERSEDED = 46,
  GENERATION_EXHAUSTED = 47,
  STORE_ERROR = 48,
  WIRE_REJECTED = 49,
  INTERNAL_ERROR = 50,
};

[[nodiscard]] std::string_view to_string(Outcome outcome) noexcept;

// True for outcomes that report an accepted, applied mutation (including the
// two no-op acceptances NO_CHANGE and IDEMPOTENT).
[[nodiscard]] bool is_acceptance(Outcome outcome) noexcept;

// Structured condition code.  Every rejection and every explanation entry is
// expressed with one of these codes; product code never reports a defect as bare
// text.  Numeric values are stable.
enum class ConditionCode : std::uint32_t {
  NONE = 0,
  // authority and scope
  AUTHORITY_EPOCH_STALE = 1,
  WORKER_FENCED = 2,
  PUBLISHER_UNKNOWN = 3,
  SCOPE_DENIED = 4,
  CAPABILITY_MISSING = 5,
  // request identity
  MALFORMED_IDENTITY = 6,
  MALFORMED_PAYLOAD = 7,
  ATTEMPT_REPLAY = 8,
  ATTEMPT_CONFLICT = 9,
  EXPECTED_MEMBERSHIP_MISMATCH = 10,
  EXPECTED_ASSIGNMENT_MISMATCH = 11,
  EXPECTED_AUTHORITY_MISMATCH = 12,
  // group and lifecycle
  GROUP_UNKNOWN = 13,
  GROUP_DUPLICATE = 14,
  GROUP_TERMINAL = 15,
  LIFECYCLE_DENIED = 16,
  PLAN_MISSING = 17,
  PLAN_STALE = 18,
  // membership
  MEMBER_DUPLICATE = 19,
  MEMBER_UNKNOWN = 20,
  MEMBER_WITHDRAWN = 21,
  MEMBER_NOT_ACTIVE = 22,
  MEMBER_DISABLED = 23,
  MEMBER_SET_LIMIT = 24,
  MIN_ACTIVE_NOT_MET = 25,
  // cost semantics
  COST_VALUE_MISMATCH = 26,
  COST_CLASS_MISMATCH = 27,
  COST_MODEL_MISMATCH = 28,
  COST_POLICY_STALE = 29,
  // upstream bindings
  PATH_AUTHORITY_STALE = 30,
  PATH_AUTHORITY_UNKNOWN = 31,
  MULTIPATH_SET_STALE = 32,
  MULTIPATH_MEMBER_ABSENT = 33,
  // consumption and limits
  GROUP_LIMIT = 34,
  BUCKET_LIMIT = 35,
  HISTORY_LIMIT = 36,
  BATCH_LIMIT = 37,
  CHURN_LIMIT = 38,
  SESSION_LIMIT = 39,
  PUBLISHER_LIMIT = 40,
  FRAME_LIMIT = 41,
  STORE_RECORD_LIMIT = 42,
  EXPLANATION_LIMIT = 43,
  GENERATION_EXHAUSTED = 44,
  // assignment
  ASSIGNMENT_UNBALANCED = 45,
  ASSIGNMENT_DUPLICATE_OWNER = 46,
  ASSIGNMENT_UNASSIGNED_BUCKET = 47,
  ASSIGNMENT_UNKNOWN_OWNER = 48,
  ASSIGNMENT_COUNT_MISMATCH = 49,
  // wire and store
  WIRE_TRUNCATED = 50,
  WIRE_TRAILING_BYTES = 51,
  WIRE_UNKNOWN_MESSAGE = 52,
  WIRE_VERSION_MISMATCH = 53,
  WIRE_INTEGRITY_FAILURE = 54,
  STORE_MAGIC = 55,
  STORE_VERSION = 56,
  STORE_INTEGRITY = 57,
  STORE_STRUCTURE = 58,
  STORE_IO = 59,
  STORE_TRAILING_BYTES = 60,
  // transport
  PEER_TIMEOUT = 61,
  PEER_CLOSED = 62,
  TRANSPORT_FAILURE = 63,
  // recovery
  RECOVERED_CONSERVATIVE = 64,
  INTERNAL_INVARIANT = 65,
  REVALIDATION_REQUIRED = 66,
};

[[nodiscard]] std::string_view to_string(ConditionCode code) noexcept;

// One structured explanatory fact.  `subject` is a short bounded token (an
// identity text, an enum name, or a bucket index); it never contains control
// characters, so rendering is stable and script friendly.
struct Condition {
  ConditionCode code = ConditionCode::NONE;
  std::string subject;
  std::uint64_t observed = 0;
  std::uint64_t expected = 0;

  [[nodiscard]] std::string render() const;

  friend bool operator==(const Condition&, const Condition&) = default;
};

[[nodiscard]] Condition make_condition(ConditionCode code, std::string subject = {},
                                       std::uint64_t observed = 0, std::uint64_t expected = 0);

// Bounded list of conditions.  Anything beyond the bound is dropped with an
// EXPLANATION_LIMIT marker so that a caller can always tell truncation happened.
class ConditionList {
 public:
  ConditionList() = default;
  explicit ConditionList(std::uint32_t max_entries) : max_entries_(max_entries) {}

  void add(Condition condition);
  [[nodiscard]] const std::vector<Condition>& entries() const noexcept { return entries_; }
  [[nodiscard]] bool empty() const noexcept { return entries_.empty(); }
  [[nodiscard]] bool truncated() const noexcept { return truncated_; }
  [[nodiscard]] std::string render() const;

 private:
  std::vector<Condition> entries_;
  std::uint32_t max_entries_ = 64;
  bool truncated_ = false;
};

// Bounded structured explanation with deterministic rendering.
class Explanation {
 public:
  Explanation() = default;
  explicit Explanation(std::string subject, std::uint32_t max_entries = 64)
      : subject_(std::move(subject)), conditions_(max_entries) {}

  void add(Condition condition);
  void set_subject(std::string subject);
  [[nodiscard]] const std::string& subject() const noexcept { return subject_; }
  [[nodiscard]] const ConditionList& conditions() const noexcept { return conditions_; }
  [[nodiscard]] bool truncated() const noexcept { return conditions_.truncated(); }
  [[nodiscard]] std::string render() const;

 private:
  std::string subject_;
  ConditionList conditions_;
};

}  // namespace ecmp
