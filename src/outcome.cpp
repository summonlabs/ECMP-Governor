#include "ecmp/outcome.hpp"

#include <string>
#include <utility>

namespace ecmp {

std::string_view to_string(Outcome outcome) noexcept {
  switch (outcome) {
    case Outcome::CREATED: return "CREATED";
    case Outcome::MEMBER_ADDED: return "MEMBER_ADDED";
    case Outcome::MEMBER_REMOVED: return "MEMBER_REMOVED";
    case Outcome::MEMBER_DISABLED: return "MEMBER_DISABLED";
    case Outcome::MEMBER_ENABLED: return "MEMBER_ENABLED";
    case Outcome::REBALANCED: return "REBALANCED";
    case Outcome::REBALANCE_PLANNED: return "REBALANCE_PLANNED";
    case Outcome::REBALANCE_ABORTED: return "REBALANCE_ABORTED";
    case Outcome::REVALIDATED: return "REVALIDATED";
    case Outcome::WITHDRAWN_OK: return "WITHDRAWN_OK";
    case Outcome::REVOKED_OK: return "REVOKED_OK";
    case Outcome::RETIRED_OK: return "RETIRED_OK";
    case Outcome::SUPERSEDED_OK: return "SUPERSEDED_OK";
    case Outcome::NO_CHANGE: return "NO_CHANGE";
    case Outcome::IDEMPOTENT: return "IDEMPOTENT";
    case Outcome::REGISTERED: return "REGISTERED";
    case Outcome::FENCED: return "FENCED";
    case Outcome::STALE_EPOCH: return "STALE_EPOCH";
    case Outcome::STALE_WORKER: return "STALE_WORKER";
    case Outcome::UNAUTHORIZED: return "UNAUTHORIZED";
    case Outcome::UNKNOWN_GROUP: return "UNKNOWN_GROUP";
    case Outcome::UNKNOWN_MEMBER: return "UNKNOWN_MEMBER";
    case Outcome::DUPLICATE_GROUP: return "DUPLICATE_GROUP";
    case Outcome::DUPLICATE_MEMBER: return "DUPLICATE_MEMBER";
    case Outcome::STALE_GROUP_GENERATION: return "STALE_GROUP_GENERATION";
    case Outcome::STALE_ASSIGNMENT_GENERATION: return "STALE_ASSIGNMENT_GENERATION";
    case Outcome::STALE_AUTHORITY_GENERATION: return "STALE_AUTHORITY_GENERATION";
    case Outcome::STALE_PATH_AUTHORITY: return "STALE_PATH_AUTHORITY";
    case Outcome::STALE_MULTIPATH_SET: return "STALE_MULTIPATH_SET";
    case Outcome::STALE_COST_GENERATION: return "STALE_COST_GENERATION";
    case Outcome::COST_MISMATCH: return "COST_MISMATCH";
    case Outcome::COST_CLASS_MISMATCH: return "COST_CLASS_MISMATCH";
    case Outcome::INSUFFICIENT_MEMBERS: return "INSUFFICIENT_MEMBERS";
    case Outcome::RESOURCE_LIMIT: return "RESOURCE_LIMIT";
    case Outcome::REVALIDATION_REQUIRED: return "REVALIDATION_REQUIRED";
    case Outcome::LIFECYCLE_VIOLATION: return "LIFECYCLE_VIOLATION";
    case Outcome::NO_PENDING_PLAN: return "NO_PENDING_PLAN";
    case Outcome::STALE_PLAN: return "STALE_PLAN";
    case Outcome::ATTEMPT_CONFLICT: return "ATTEMPT_CONFLICT";
    case Outcome::MALFORMED_REQUEST: return "MALFORMED_REQUEST";
    case Outcome::REVOKED: return "REVOKED";
    case Outcome::RETIRED: return "RETIRED";
    case Outcome::WITHDRAWN: return "WITHDRAWN";
    case Outcome::SUPERSEDED: return "SUPERSEDED";
    case Outcome::GENERATION_EXHAUSTED: return "GENERATION_EXHAUSTED";
    case Outcome::STORE_ERROR: return "STORE_ERROR";
    case Outcome::WIRE_REJECTED: return "WIRE_REJECTED";
    case Outcome::INTERNAL_ERROR: return "INTERNAL_ERROR";
  }
  return "UNKNOWN_OUTCOME";
}

bool is_acceptance(Outcome outcome) noexcept {
  return static_cast<std::uint32_t>(outcome) < 20u;
}

std::string_view to_string(ConditionCode code) noexcept {
  switch (code) {
    case ConditionCode::NONE: return "NONE";
    case ConditionCode::AUTHORITY_EPOCH_STALE: return "AUTHORITY_EPOCH_STALE";
    case ConditionCode::WORKER_FENCED: return "WORKER_FENCED";
    case ConditionCode::PUBLISHER_UNKNOWN: return "PUBLISHER_UNKNOWN";
    case ConditionCode::SCOPE_DENIED: return "SCOPE_DENIED";
    case ConditionCode::CAPABILITY_MISSING: return "CAPABILITY_MISSING";
    case ConditionCode::MALFORMED_IDENTITY: return "MALFORMED_IDENTITY";
    case ConditionCode::MALFORMED_PAYLOAD: return "MALFORMED_PAYLOAD";
    case ConditionCode::ATTEMPT_REPLAY: return "ATTEMPT_REPLAY";
    case ConditionCode::ATTEMPT_CONFLICT: return "ATTEMPT_CONFLICT";
    case ConditionCode::EXPECTED_MEMBERSHIP_MISMATCH: return "EXPECTED_MEMBERSHIP_MISMATCH";
    case ConditionCode::EXPECTED_ASSIGNMENT_MISMATCH: return "EXPECTED_ASSIGNMENT_MISMATCH";
    case ConditionCode::EXPECTED_AUTHORITY_MISMATCH: return "EXPECTED_AUTHORITY_MISMATCH";
    case ConditionCode::GROUP_UNKNOWN: return "GROUP_UNKNOWN";
    case ConditionCode::GROUP_DUPLICATE: return "GROUP_DUPLICATE";
    case ConditionCode::GROUP_TERMINAL: return "GROUP_TERMINAL";
    case ConditionCode::LIFECYCLE_DENIED: return "LIFECYCLE_DENIED";
    case ConditionCode::PLAN_MISSING: return "PLAN_MISSING";
    case ConditionCode::PLAN_STALE: return "PLAN_STALE";
    case ConditionCode::MEMBER_DUPLICATE: return "MEMBER_DUPLICATE";
    case ConditionCode::MEMBER_UNKNOWN: return "MEMBER_UNKNOWN";
    case ConditionCode::MEMBER_WITHDRAWN: return "MEMBER_WITHDRAWN";
    case ConditionCode::MEMBER_NOT_ACTIVE: return "MEMBER_NOT_ACTIVE";
    case ConditionCode::MEMBER_DISABLED: return "MEMBER_DISABLED";
    case ConditionCode::MEMBER_SET_LIMIT: return "MEMBER_SET_LIMIT";
    case ConditionCode::MIN_ACTIVE_NOT_MET: return "MIN_ACTIVE_NOT_MET";
    case ConditionCode::COST_VALUE_MISMATCH: return "COST_VALUE_MISMATCH";
    case ConditionCode::COST_CLASS_MISMATCH: return "COST_CLASS_MISMATCH";
    case ConditionCode::COST_MODEL_MISMATCH: return "COST_MODEL_MISMATCH";
    case ConditionCode::COST_POLICY_STALE: return "COST_POLICY_STALE";
    case ConditionCode::PATH_AUTHORITY_STALE: return "PATH_AUTHORITY_STALE";
    case ConditionCode::PATH_AUTHORITY_UNKNOWN: return "PATH_AUTHORITY_UNKNOWN";
    case ConditionCode::MULTIPATH_SET_STALE: return "MULTIPATH_SET_STALE";
    case ConditionCode::MULTIPATH_MEMBER_ABSENT: return "MULTIPATH_MEMBER_ABSENT";
    case ConditionCode::GROUP_LIMIT: return "GROUP_LIMIT";
    case ConditionCode::BUCKET_LIMIT: return "BUCKET_LIMIT";
    case ConditionCode::HISTORY_LIMIT: return "HISTORY_LIMIT";
    case ConditionCode::BATCH_LIMIT: return "BATCH_LIMIT";
    case ConditionCode::CHURN_LIMIT: return "CHURN_LIMIT";
    case ConditionCode::SESSION_LIMIT: return "SESSION_LIMIT";
    case ConditionCode::PUBLISHER_LIMIT: return "PUBLISHER_LIMIT";
    case ConditionCode::FRAME_LIMIT: return "FRAME_LIMIT";
    case ConditionCode::STORE_RECORD_LIMIT: return "STORE_RECORD_LIMIT";
    case ConditionCode::EXPLANATION_LIMIT: return "EXPLANATION_LIMIT";
    case ConditionCode::GENERATION_EXHAUSTED: return "GENERATION_EXHAUSTED";
    case ConditionCode::ASSIGNMENT_UNBALANCED: return "ASSIGNMENT_UNBALANCED";
    case ConditionCode::ASSIGNMENT_DUPLICATE_OWNER: return "ASSIGNMENT_DUPLICATE_OWNER";
    case ConditionCode::ASSIGNMENT_UNASSIGNED_BUCKET: return "ASSIGNMENT_UNASSIGNED_BUCKET";
    case ConditionCode::ASSIGNMENT_UNKNOWN_OWNER: return "ASSIGNMENT_UNKNOWN_OWNER";
    case ConditionCode::ASSIGNMENT_COUNT_MISMATCH: return "ASSIGNMENT_COUNT_MISMATCH";
    case ConditionCode::WIRE_TRUNCATED: return "WIRE_TRUNCATED";
    case ConditionCode::WIRE_TRAILING_BYTES: return "WIRE_TRAILING_BYTES";
    case ConditionCode::WIRE_UNKNOWN_MESSAGE: return "WIRE_UNKNOWN_MESSAGE";
    case ConditionCode::WIRE_VERSION_MISMATCH: return "WIRE_VERSION_MISMATCH";
    case ConditionCode::WIRE_INTEGRITY_FAILURE: return "WIRE_INTEGRITY_FAILURE";
    case ConditionCode::STORE_MAGIC: return "STORE_MAGIC";
    case ConditionCode::STORE_VERSION: return "STORE_VERSION";
    case ConditionCode::STORE_INTEGRITY: return "STORE_INTEGRITY";
    case ConditionCode::STORE_STRUCTURE: return "STORE_STRUCTURE";
    case ConditionCode::STORE_IO: return "STORE_IO";
    case ConditionCode::STORE_TRAILING_BYTES: return "STORE_TRAILING_BYTES";
    case ConditionCode::PEER_TIMEOUT: return "PEER_TIMEOUT";
    case ConditionCode::PEER_CLOSED: return "PEER_CLOSED";
    case ConditionCode::TRANSPORT_FAILURE: return "TRANSPORT_FAILURE";
    case ConditionCode::RECOVERED_CONSERVATIVE: return "RECOVERED_CONSERVATIVE";
    case ConditionCode::INTERNAL_INVARIANT: return "INTERNAL_INVARIANT";
    case ConditionCode::REVALIDATION_REQUIRED: return "REVALIDATION_REQUIRED";
  }
  return "UNKNOWN_CONDITION";
}

std::string Condition::render() const {
  std::string out(to_string(code));
  if (!subject.empty()) {
    out += " subject=";
    out += subject;
  }
  out += " observed=";
  out += std::to_string(observed);
  out += " expected=";
  out += std::to_string(expected);
  return out;
}

Condition make_condition(ConditionCode code, std::string subject, std::uint64_t observed,
                         std::uint64_t expected) {
  Condition condition;
  condition.code = code;
  condition.subject = std::move(subject);
  condition.observed = observed;
  condition.expected = expected;
  return condition;
}

void ConditionList::add(Condition condition) {
  if (entries_.size() >= max_entries_) {
    truncated_ = true;
    return;
  }
  entries_.push_back(std::move(condition));
}

std::string ConditionList::render() const {
  std::string out;
  for (const Condition& condition : entries_) {
    out += condition.render();
    out += '\n';
  }
  if (truncated_) {
    out += "EXPLANATION_LIMIT truncated=true\n";
  }
  return out;
}

void Explanation::add(Condition condition) { conditions_.add(std::move(condition)); }

void Explanation::set_subject(std::string subject) { subject_ = std::move(subject); }

std::string Explanation::render() const {
  std::string out = "explanation ";
  out += subject_.empty() ? std::string("(none)") : subject_;
  out += '\n';
  out += conditions_.render();
  return out;
}

}  // namespace ecmp
