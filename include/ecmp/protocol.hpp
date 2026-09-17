#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "ecmp/authority.hpp"
#include "ecmp/bytes.hpp"
#include "ecmp/governor.hpp"
#include "ecmp/limits.hpp"
#include "ecmp/version.hpp"

namespace ecmp {

// Stable explicit wire message identifiers.  Numeric values are part of the
// protocol contract: they are never renumbered and never derived from a C++ enum
// ordinal.
enum class WireMessageId : std::uint16_t {
  HELLO = 0x0001,
  HELLO_RESPONSE = 0x0002,
  REGISTER_PUBLISHER = 0x0010,
  REGISTER_PUBLISHER_RESPONSE = 0x0011,
  CREATE_GROUP = 0x0020,
  CREATE_GROUP_RESPONSE = 0x0021,
  ADD_MEMBER = 0x0022,
  ADD_MEMBER_RESPONSE = 0x0023,
  REMOVE_MEMBER = 0x0024,
  REMOVE_MEMBER_RESPONSE = 0x0025,
  DISABLE_MEMBER = 0x0026,
  DISABLE_MEMBER_RESPONSE = 0x0027,
  ENABLE_MEMBER = 0x0028,
  ENABLE_MEMBER_RESPONSE = 0x0029,
  REVALIDATE_GROUP = 0x002A,
  REVALIDATE_GROUP_RESPONSE = 0x002B,
  PLAN_REBALANCE = 0x002C,
  PLAN_REBALANCE_RESPONSE = 0x002D,
  COMMIT_REBALANCE = 0x002E,
  REBALANCE_RESULT = 0x002F,
  QUERY_GROUP = 0x0030,
  QUERY_GROUP_RESPONSE = 0x0031,
  SNAPSHOT_REQUEST = 0x0032,
  SNAPSHOT_RESPONSE = 0x0033,
  LIST_GROUPS = 0x0034,
  LIST_GROUPS_RESPONSE = 0x0035,
  FENCE_NOTICE = 0x0036,
  ERROR = 0x0037,
  // Upstream feed: the Path Authority domain reports a new generation for an exact
  // path.  The coordinator re-observes through its own Path Authority view; the
  // notice itself is never treated as an observation.
  PATH_AUTHORITY_CHANGE = 0x0040,
  PATH_AUTHORITY_CHANGE_RESPONSE = 0x0041,
  EXPLAIN_REQUEST = 0x0050,
  EXPLAIN_RESPONSE = 0x0051,
};

// Operator explanation selectors.  Numeric values are stable wire identifiers.
enum class ExplainKind : std::uint32_t {
  GROUP = 1,
  MEMBER = 2,
  BUCKET = 3,
  LAST_REBALANCE = 4,
  AUTHORITY = 5,
};

struct ExplainRequest {
  ECMPGroupId group;
  ExplainKind kind = ExplainKind::GROUP;
  ECMPMemberId member;
  BucketId bucket;
};

struct ExplainResponseBody {
  bool found = false;
  std::string text;
};

[[nodiscard]] std::string_view to_string(WireMessageId id) noexcept;
[[nodiscard]] bool is_known_message(std::uint16_t raw) noexcept;
[[nodiscard]] bool is_response(WireMessageId id) noexcept;

class Envelope {
 public:
  WireMessageId message = WireMessageId::ERROR;
  CoordinatorEpoch epoch;
  PublisherId publisher;
  WorkerBootId worker_boot;
  MutationAttemptId attempt;
  std::vector<std::uint8_t> payload;

  [[nodiscard]] MutationAttemptId attempt_or_default() const;
};

enum class WireDefect : std::uint32_t {
  NONE = 0,
  TRUNCATED = 1,
  TRAILING_BYTES = 2,
  UNKNOWN_MESSAGE = 3,
  VERSION_MISMATCH = 4,
  INTEGRITY_FAILURE = 5,
  FRAME_TOO_LARGE = 6,
  MALFORMED_PAYLOAD = 7,
  BAD_MAGIC = 8,
  RESERVED_NOT_ZERO = 9,
  PEER_TIMEOUT = 10,
  PEER_CLOSED = 11,
};

[[nodiscard]] std::string_view to_string(WireDefect defect) noexcept;
[[nodiscard]] ConditionCode condition_for(WireDefect defect) noexcept;

inline constexpr std::size_t kWireHeaderBytes = 76;
inline constexpr std::size_t kWireTagBytes = 32;
inline constexpr std::size_t kWireOverheadBytes = kWireHeaderBytes + kWireTagBytes;

// Complete frame codec.  `decode_frame` consumes exactly one frame and rejects
// trailing bytes, unknown message ids, a wrong wire version, a non-zero reserved
// field, an over-long payload and any integrity mismatch.
[[nodiscard]] std::vector<std::uint8_t> encode_frame(const Envelope& envelope,
                                                     const GovernorLimits& limits);

[[nodiscard]] WireDefect decode_frame(std::span<const std::uint8_t> bytes,
                                      const GovernorLimits& limits, Envelope& out);

// --- payload codecs ---------------------------------------------------------
// Each request payload carries only the semantic fields; the authority context
// travels in the envelope.  Every decoder rejects trailing bytes and every
// out-of-range enum value.

[[nodiscard]] std::vector<std::uint8_t> encode_payload(const ExplainRequest& request);
[[nodiscard]] bool decode_payload(std::span<const std::uint8_t> bytes,
                                  const GovernorLimits& limits, ExplainRequest& out);
[[nodiscard]] std::vector<std::uint8_t> encode_explain_response(const ExplainResponseBody& body);
[[nodiscard]] bool decode_explain_response(std::span<const std::uint8_t> bytes,
                                           const GovernorLimits& limits,
                                           ExplainResponseBody& out);
[[nodiscard]] std::vector<std::uint8_t> encode_payload(const PublisherRegistration& registration);
[[nodiscard]] bool decode_payload(std::span<const std::uint8_t> bytes,
                                  const GovernorLimits& limits, PublisherRegistration& out);
[[nodiscard]] std::vector<std::uint8_t> encode_payload(const ECMPGroupId& group);
[[nodiscard]] bool decode_payload(std::span<const std::uint8_t> bytes,
                                  const GovernorLimits& limits, ECMPGroupId& out);
[[nodiscard]] std::vector<std::uint8_t> encode_payload(const CreateGroupRequest& request);
[[nodiscard]] std::vector<std::uint8_t> encode_payload(const AddMemberRequest& request);
[[nodiscard]] std::vector<std::uint8_t> encode_payload(const RemoveMemberRequest& request);
[[nodiscard]] std::vector<std::uint8_t> encode_payload(const SetMemberEnabledRequest& request);
[[nodiscard]] std::vector<std::uint8_t> encode_payload(const MembershipSetRequest& request);
[[nodiscard]] std::vector<std::uint8_t> encode_payload(const RevalidateGroupRequest& request);
[[nodiscard]] std::vector<std::uint8_t> encode_payload(const RebalancePlanRequest& request);
[[nodiscard]] std::vector<std::uint8_t> encode_payload(const RebalanceCommitRequest& request);
[[nodiscard]] std::vector<std::uint8_t> encode_payload(const RebalanceAbortRequest& request);
[[nodiscard]] std::vector<std::uint8_t> encode_payload(const GroupAdminRequest& request);
[[nodiscard]] std::vector<std::uint8_t> encode_payload(const PathAuthorityChangeNotice& notice);
[[nodiscard]] std::vector<std::uint8_t> encode_payload(const MultipathSetChangeNotice& notice);
[[nodiscard]] std::vector<std::uint8_t> encode_payload(const CostGenerationChangeNotice& notice);

[[nodiscard]] bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                                  CreateGroupRequest& out);
[[nodiscard]] bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                                  AddMemberRequest& out);
[[nodiscard]] bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                                  RemoveMemberRequest& out);
[[nodiscard]] bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                                  SetMemberEnabledRequest& out);
[[nodiscard]] bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                                  MembershipSetRequest& out);
[[nodiscard]] bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                                  RevalidateGroupRequest& out);
[[nodiscard]] bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                                  RebalancePlanRequest& out);
[[nodiscard]] bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                                  RebalanceCommitRequest& out);
[[nodiscard]] bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                                  RebalanceAbortRequest& out);
[[nodiscard]] bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                                  GroupAdminRequest& out);
[[nodiscard]] bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                                  PathAuthorityChangeNotice& out);
[[nodiscard]] bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                                  MultipathSetChangeNotice& out);
[[nodiscard]] bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                                  CostGenerationChangeNotice& out);

// --- shared value codecs ----------------------------------------------------
void encode_group_key(Encoder& encoder, const GroupKey& key);
[[nodiscard]] bool decode_group_key(Decoder& decoder, GroupKey& out);
void encode_member_spec(Encoder& encoder, const MemberSpec& spec);
[[nodiscard]] bool decode_member_spec(Decoder& decoder, const GovernorLimits& limits, MemberSpec& out);
void encode_member_record(Encoder& encoder, const MemberRecord& record);
[[nodiscard]] bool decode_member_record(Decoder& decoder, const GovernorLimits& limits,
                                        MemberRecord& out);
void encode_cost_claim(Encoder& encoder, const CostClaim& claim);
[[nodiscard]] bool decode_cost_claim(Decoder& decoder, CostClaim& out);
void encode_bucket_assignment(Encoder& encoder, const BucketAssignment& assignment);
[[nodiscard]] bool decode_bucket_assignment(Decoder& decoder, const GovernorLimits& limits,
                                            BucketAssignment& out);
void encode_condition_list(Encoder& encoder, const ConditionList& conditions);
[[nodiscard]] bool decode_condition_list(Decoder& decoder, const GovernorLimits& limits,
                                         ConditionList& out);
void encode_mutation_result(Encoder& encoder, const MutationResult& result);
[[nodiscard]] bool decode_mutation_result(Decoder& decoder, const GovernorLimits& limits,
                                          MutationResult& out);
[[nodiscard]] std::vector<std::uint8_t> encode_mutation_result(const MutationResult& result);
[[nodiscard]] bool decode_mutation_result(std::span<const std::uint8_t> bytes,
                                          const GovernorLimits& limits, MutationResult& out);
void encode_group_summary(Encoder& encoder, const GroupSummary& summary);
[[nodiscard]] bool decode_group_summary(Decoder& decoder, const GovernorLimits& limits,
                                        GroupSummary& out);
void encode_group_snapshot(Encoder& encoder, const GroupSnapshot& snapshot);
[[nodiscard]] bool decode_group_snapshot(Decoder& decoder, const GovernorLimits& limits,
                                         GroupSnapshot& out);
void encode_bucket_move(Encoder& encoder, const BucketMove& move);
[[nodiscard]] bool decode_bucket_move(Decoder& decoder, BucketMove& out);
void encode_rebalance_record(Encoder& encoder, const RebalanceRecord& record);
[[nodiscard]] bool decode_rebalance_record(Decoder& decoder, const GovernorLimits& limits,
                                           RebalanceRecord& out);

// Response payload bodies.
struct HelloResponseBody {
  std::uint32_t wire_version = 0;
  CoordinatorEpoch epoch;
  std::string product;
  std::string version;
};

struct RegisterPublisherResponseBody {
  Outcome outcome = Outcome::UNAUTHORIZED;
  ConditionList conditions;
};

struct SnapshotResponseBody {
  bool found = false;
  GroupSnapshot snapshot;
};

struct ListGroupsResponseBody {
  std::vector<GroupSummary> groups;
};

// QUERY_GROUP answers with the compact summary; SNAPSHOT_REQUEST answers with the
// complete immutable snapshot.  Both shapes are explicit and separately encoded.
struct GroupQueryResponseBody {
  bool found = false;
  GroupSummary summary;
};

struct RebalanceResultBody {
  MutationResult result;
  RebalanceRecord record;
};

struct ErrorBody {
  ConditionCode code = ConditionCode::NONE;
  Outcome outcome = Outcome::INTERNAL_ERROR;
  std::string detail;
};

[[nodiscard]] std::vector<std::uint8_t> encode_hello_response(const HelloResponseBody& body);
[[nodiscard]] bool decode_hello_response(std::span<const std::uint8_t> bytes,
                                         const GovernorLimits& limits, HelloResponseBody& out);
[[nodiscard]] std::vector<std::uint8_t> encode_register_publisher_response(
    const RegisterPublisherResponseBody& body);
[[nodiscard]] bool decode_register_publisher_response(std::span<const std::uint8_t> bytes,
                                                      const GovernorLimits& limits,
                                                      RegisterPublisherResponseBody& out);
[[nodiscard]] std::vector<std::uint8_t> encode_snapshot_response(const SnapshotResponseBody& body);
[[nodiscard]] bool decode_snapshot_response(std::span<const std::uint8_t> bytes,
                                            const GovernorLimits& limits,
                                            SnapshotResponseBody& out);
[[nodiscard]] std::vector<std::uint8_t> encode_group_query_response(
    const GroupQueryResponseBody& body);
[[nodiscard]] bool decode_group_query_response(std::span<const std::uint8_t> bytes,
                                               const GovernorLimits& limits,
                                               GroupQueryResponseBody& out);
[[nodiscard]] std::vector<std::uint8_t> encode_list_groups_response(
    const ListGroupsResponseBody& body);
[[nodiscard]] bool decode_list_groups_response(std::span<const std::uint8_t> bytes,
                                               const GovernorLimits& limits,
                                               ListGroupsResponseBody& out);
[[nodiscard]] std::vector<std::uint8_t> encode_rebalance_result(const RebalanceResultBody& body);
[[nodiscard]] bool decode_rebalance_result(std::span<const std::uint8_t> bytes,
                                           const GovernorLimits& limits, RebalanceResultBody& out);
[[nodiscard]] std::vector<std::uint8_t> encode_error_body(const ErrorBody& body);
[[nodiscard]] bool decode_error_body(std::span<const std::uint8_t> bytes,
                                     const GovernorLimits& limits, ErrorBody& out);

}  // namespace ecmp
