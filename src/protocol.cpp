#include "ecmp/protocol.hpp"

#include <algorithm>
#include <array>
#include <string>
#include <vector>

#include "ecmp/bytes.hpp"
#include "ecmp/digest.hpp"

namespace ecmp {
namespace {

constexpr std::string_view kWireIntegrityDomain = "ecmp.wire.v1";
constexpr std::uint8_t kMagic[4] = {'E', 'C', 'M', 'P'};
constexpr std::size_t kMaxTextBytes = 256;
constexpr std::size_t kMaxSubjectBytes = 64;

void encode_ids(Encoder& encoder, const PathId& path, const ECMPMemberId& member) {
  encoder.raw(path.bytes());
  encoder.raw(member.bytes());
}

bool decode_state(Decoder& decoder, MemberState& out) {
  std::uint8_t raw = 0;
  if (!decoder.u8(raw)) {
    return false;
  }
  if (raw < 1 || raw > kMemberStateCount) {
    return false;
  }
  out = static_cast<MemberState>(raw);
  return true;
}

bool decode_lifecycle(Decoder& decoder, GroupLifecycle& out) {
  std::uint8_t raw = 0;
  if (!decoder.u8(raw)) {
    return false;
  }
  if (raw < 1 || raw > kGroupLifecycleCount) {
    return false;
  }
  out = static_cast<GroupLifecycle>(raw);
  return true;
}

bool decode_source(Decoder& decoder, MembershipSource& out) {
  std::uint8_t raw = 0;
  if (!decoder.u8(raw)) {
    return false;
  }
  if (raw < 1 || raw > 2) {
    return false;
  }
  out = static_cast<MembershipSource>(raw);
  return true;
}

bool decode_scope_kind(Decoder& decoder, ScopeKind& out) {
  std::uint8_t raw = 0;
  if (!decoder.u8(raw)) {
    return false;
  }
  if (raw > 4) {
    return false;
  }
  out = static_cast<ScopeKind>(raw);
  return true;
}

bool decode_plan_id(Decoder& decoder, RebalancePlanId& out) {
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out = RebalancePlanId::from_bytes(raw);
  return true;
}

void encode_move_reason(Encoder& encoder, MoveReason reason) {
  encoder.u8(static_cast<std::uint8_t>(reason));
}

bool decode_move_reason(Decoder& decoder, MoveReason& out) {
  std::uint8_t raw = 0;
  if (!decoder.u8(raw)) {
    return false;
  }
  if (raw < 1 || raw > 3) {
    return false;
  }
  out = static_cast<MoveReason>(raw);
  return true;
}

void encode_change_reason(Encoder& encoder, ChangeReason reason) {
  encoder.u8(static_cast<std::uint8_t>(reason));
}

bool decode_change_reason(Decoder& decoder, ChangeReason& out) {
  std::uint8_t raw = 0;
  if (!decoder.u8(raw)) {
    return false;
  }
  if (raw < 1 || raw > 16) {
    return false;
  }
  out = static_cast<ChangeReason>(raw);
  return true;
}

}  // namespace

std::string_view to_string(WireMessageId id) noexcept {
  switch (id) {
    case WireMessageId::HELLO: return "HELLO";
    case WireMessageId::HELLO_RESPONSE: return "HELLO_RESPONSE";
    case WireMessageId::REGISTER_PUBLISHER: return "REGISTER_PUBLISHER";
    case WireMessageId::REGISTER_PUBLISHER_RESPONSE: return "REGISTER_PUBLISHER_RESPONSE";
    case WireMessageId::CREATE_GROUP: return "CREATE_GROUP";
    case WireMessageId::CREATE_GROUP_RESPONSE: return "CREATE_GROUP_RESPONSE";
    case WireMessageId::ADD_MEMBER: return "ADD_MEMBER";
    case WireMessageId::ADD_MEMBER_RESPONSE: return "ADD_MEMBER_RESPONSE";
    case WireMessageId::REMOVE_MEMBER: return "REMOVE_MEMBER";
    case WireMessageId::REMOVE_MEMBER_RESPONSE: return "REMOVE_MEMBER_RESPONSE";
    case WireMessageId::DISABLE_MEMBER: return "DISABLE_MEMBER";
    case WireMessageId::DISABLE_MEMBER_RESPONSE: return "DISABLE_MEMBER_RESPONSE";
    case WireMessageId::ENABLE_MEMBER: return "ENABLE_MEMBER";
    case WireMessageId::ENABLE_MEMBER_RESPONSE: return "ENABLE_MEMBER_RESPONSE";
    case WireMessageId::REVALIDATE_GROUP: return "REVALIDATE_GROUP";
    case WireMessageId::REVALIDATE_GROUP_RESPONSE: return "REVALIDATE_GROUP_RESPONSE";
    case WireMessageId::PLAN_REBALANCE: return "PLAN_REBALANCE";
    case WireMessageId::PLAN_REBALANCE_RESPONSE: return "PLAN_REBALANCE_RESPONSE";
    case WireMessageId::COMMIT_REBALANCE: return "COMMIT_REBALANCE";
    case WireMessageId::REBALANCE_RESULT: return "REBALANCE_RESULT";
    case WireMessageId::QUERY_GROUP: return "QUERY_GROUP";
    case WireMessageId::QUERY_GROUP_RESPONSE: return "QUERY_GROUP_RESPONSE";
    case WireMessageId::SNAPSHOT_REQUEST: return "SNAPSHOT_REQUEST";
    case WireMessageId::SNAPSHOT_RESPONSE: return "SNAPSHOT_RESPONSE";
    case WireMessageId::LIST_GROUPS: return "LIST_GROUPS";
    case WireMessageId::LIST_GROUPS_RESPONSE: return "LIST_GROUPS_RESPONSE";
    case WireMessageId::FENCE_NOTICE: return "FENCE_NOTICE";
    case WireMessageId::ERROR: return "ERROR";
    case WireMessageId::PATH_AUTHORITY_CHANGE: return "PATH_AUTHORITY_CHANGE";
    case WireMessageId::PATH_AUTHORITY_CHANGE_RESPONSE: return "PATH_AUTHORITY_CHANGE_RESPONSE";
    case WireMessageId::EXPLAIN_REQUEST: return "EXPLAIN_REQUEST";
    case WireMessageId::EXPLAIN_RESPONSE: return "EXPLAIN_RESPONSE";
  }
  return "UNKNOWN_MESSAGE";
}

bool is_known_message(std::uint16_t raw) noexcept {
  switch (static_cast<WireMessageId>(raw)) {
    case WireMessageId::HELLO:
    case WireMessageId::HELLO_RESPONSE:
    case WireMessageId::REGISTER_PUBLISHER:
    case WireMessageId::REGISTER_PUBLISHER_RESPONSE:
    case WireMessageId::CREATE_GROUP:
    case WireMessageId::CREATE_GROUP_RESPONSE:
    case WireMessageId::ADD_MEMBER:
    case WireMessageId::ADD_MEMBER_RESPONSE:
    case WireMessageId::REMOVE_MEMBER:
    case WireMessageId::REMOVE_MEMBER_RESPONSE:
    case WireMessageId::DISABLE_MEMBER:
    case WireMessageId::DISABLE_MEMBER_RESPONSE:
    case WireMessageId::ENABLE_MEMBER:
    case WireMessageId::ENABLE_MEMBER_RESPONSE:
    case WireMessageId::REVALIDATE_GROUP:
    case WireMessageId::REVALIDATE_GROUP_RESPONSE:
    case WireMessageId::PLAN_REBALANCE:
    case WireMessageId::PLAN_REBALANCE_RESPONSE:
    case WireMessageId::COMMIT_REBALANCE:
    case WireMessageId::REBALANCE_RESULT:
    case WireMessageId::QUERY_GROUP:
    case WireMessageId::QUERY_GROUP_RESPONSE:
    case WireMessageId::SNAPSHOT_REQUEST:
    case WireMessageId::SNAPSHOT_RESPONSE:
    case WireMessageId::LIST_GROUPS:
    case WireMessageId::LIST_GROUPS_RESPONSE:
    case WireMessageId::FENCE_NOTICE:
    case WireMessageId::ERROR:
    case WireMessageId::PATH_AUTHORITY_CHANGE:
    case WireMessageId::PATH_AUTHORITY_CHANGE_RESPONSE:
    case WireMessageId::EXPLAIN_REQUEST:
    case WireMessageId::EXPLAIN_RESPONSE:
      return true;
    default:
      return false;
  }
}

bool is_response(WireMessageId id) noexcept {
  switch (id) {
    case WireMessageId::HELLO_RESPONSE:
    case WireMessageId::REGISTER_PUBLISHER_RESPONSE:
    case WireMessageId::CREATE_GROUP_RESPONSE:
    case WireMessageId::ADD_MEMBER_RESPONSE:
    case WireMessageId::REMOVE_MEMBER_RESPONSE:
    case WireMessageId::DISABLE_MEMBER_RESPONSE:
    case WireMessageId::ENABLE_MEMBER_RESPONSE:
    case WireMessageId::REVALIDATE_GROUP_RESPONSE:
    case WireMessageId::PLAN_REBALANCE_RESPONSE:
    case WireMessageId::REBALANCE_RESULT:
    case WireMessageId::QUERY_GROUP_RESPONSE:
    case WireMessageId::SNAPSHOT_RESPONSE:
    case WireMessageId::LIST_GROUPS_RESPONSE:
    case WireMessageId::FENCE_NOTICE:
    case WireMessageId::ERROR:
    case WireMessageId::PATH_AUTHORITY_CHANGE_RESPONSE:
    case WireMessageId::EXPLAIN_RESPONSE:
      return true;
    default:
      return false;
  }
}

std::string_view to_string(WireDefect defect) noexcept {
  switch (defect) {
    case WireDefect::NONE: return "NONE";
    case WireDefect::TRUNCATED: return "TRUNCATED";
    case WireDefect::TRAILING_BYTES: return "TRAILING_BYTES";
    case WireDefect::UNKNOWN_MESSAGE: return "UNKNOWN_MESSAGE";
    case WireDefect::VERSION_MISMATCH: return "VERSION_MISMATCH";
    case WireDefect::INTEGRITY_FAILURE: return "INTEGRITY_FAILURE";
    case WireDefect::FRAME_TOO_LARGE: return "FRAME_TOO_LARGE";
    case WireDefect::MALFORMED_PAYLOAD: return "MALFORMED_PAYLOAD";
    case WireDefect::BAD_MAGIC: return "BAD_MAGIC";
    case WireDefect::RESERVED_NOT_ZERO: return "RESERVED_NOT_ZERO";
    case WireDefect::PEER_TIMEOUT: return "PEER_TIMEOUT";
    case WireDefect::PEER_CLOSED: return "PEER_CLOSED";
  }
  return "UNKNOWN_WIRE_DEFECT";
}

ConditionCode condition_for(WireDefect defect) noexcept {
  switch (defect) {
    case WireDefect::NONE: return ConditionCode::NONE;
    case WireDefect::TRUNCATED: return ConditionCode::WIRE_TRUNCATED;
    case WireDefect::TRAILING_BYTES: return ConditionCode::WIRE_TRAILING_BYTES;
    case WireDefect::UNKNOWN_MESSAGE: return ConditionCode::WIRE_UNKNOWN_MESSAGE;
    case WireDefect::VERSION_MISMATCH: return ConditionCode::WIRE_VERSION_MISMATCH;
    case WireDefect::INTEGRITY_FAILURE: return ConditionCode::WIRE_INTEGRITY_FAILURE;
    case WireDefect::FRAME_TOO_LARGE: return ConditionCode::FRAME_LIMIT;
    case WireDefect::MALFORMED_PAYLOAD: return ConditionCode::MALFORMED_PAYLOAD;
    case WireDefect::BAD_MAGIC: return ConditionCode::WIRE_UNKNOWN_MESSAGE;
    case WireDefect::RESERVED_NOT_ZERO: return ConditionCode::MALFORMED_PAYLOAD;
    case WireDefect::PEER_TIMEOUT: return ConditionCode::PEER_TIMEOUT;
    case WireDefect::PEER_CLOSED: return ConditionCode::PEER_CLOSED;
  }
  return ConditionCode::WIRE_INTEGRITY_FAILURE;
}

MutationAttemptId Envelope::attempt_or_default() const {
  if (!attempt.is_nil()) {
    return attempt;
  }
  Encoder encoder;
  encoder.raw(publisher.bytes());
  encoder.raw(worker_boot.bytes());
  encoder.u16(static_cast<std::uint16_t>(message));
  encoder.raw(payload);
  const Digest digest = domain_digest("ecmp.attempt.default.v1", encoder.bytes());
  std::array<std::uint8_t, 16> raw{};
  std::copy(digest.bytes().begin(), digest.bytes().begin() + 16, raw.begin());
  return MutationAttemptId::from_bytes(raw);
}

std::vector<std::uint8_t> encode_frame(const Envelope& envelope, const GovernorLimits& limits) {
  if (envelope.payload.size() > limits.max_frame_bytes) {
    return {};
  }
  Encoder encoder(limits.max_frame_bytes);
  encoder.u8(kMagic[0]);
  encoder.u8(kMagic[1]);
  encoder.u8(kMagic[2]);
  encoder.u8(kMagic[3]);
  encoder.u16(static_cast<std::uint16_t>(kWireVersion));
  encoder.u16(static_cast<std::uint16_t>(envelope.message));
  encoder.u32(0);
  encoder.u32(static_cast<std::uint32_t>(envelope.payload.size()));
  encoder.u64(envelope.epoch.value());
  encoder.fixed16(envelope.publisher.bytes());
  encoder.fixed16(envelope.worker_boot.bytes());
  encoder.fixed16(envelope.attempt.bytes());
  encoder.u32(0);
  encoder.raw(envelope.payload);
  const Digest tag = domain_digest(kWireIntegrityDomain, encoder.bytes());
  encoder.raw(tag.bytes());
  return encoder.take();
}

WireDefect decode_frame(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                        Envelope& out) {
  if (bytes.size() < kWireOverheadBytes) {
    return WireDefect::TRUNCATED;
  }
  Decoder decoder(bytes, limits.max_frame_bytes);
  for (const std::uint8_t expected : kMagic) {
    std::uint8_t actual = 0;
    if (!decoder.u8(actual)) {
      return WireDefect::TRUNCATED;
    }
    if (actual != expected) {
      return WireDefect::BAD_MAGIC;
    }
  }
  std::uint16_t version = 0;
  std::uint16_t raw_message = 0;
  std::uint32_t flags = 0;
  std::uint32_t payload_length = 0;
  std::uint64_t epoch = 0;
  std::array<std::uint8_t, 16> publisher{};
  std::array<std::uint8_t, 16> worker_boot{};
  std::array<std::uint8_t, 16> attempt{};
  std::uint32_t reserved = 0;
  if (!decoder.u16(version) || !decoder.u16(raw_message) || !decoder.u32(flags) ||
      !decoder.u32(payload_length) || !decoder.u64(epoch) ||
      !decoder.fixed16(publisher) || !decoder.fixed16(worker_boot) ||
      !decoder.fixed16(attempt) || !decoder.u32(reserved)) {
    return WireDefect::TRUNCATED;
  }
  if (version != kWireVersion) {
    return WireDefect::VERSION_MISMATCH;
  }
  if (!is_known_message(raw_message)) {
    return WireDefect::UNKNOWN_MESSAGE;
  }
  if (reserved != 0) {
    return WireDefect::RESERVED_NOT_ZERO;
  }
  if (payload_length > limits.max_frame_bytes) {
    return WireDefect::FRAME_TOO_LARGE;
  }
  const std::size_t expected_size = kWireOverheadBytes + payload_length;
  if (bytes.size() < expected_size) {
    return WireDefect::TRUNCATED;
  }
  if (bytes.size() > expected_size) {
    return WireDefect::TRAILING_BYTES;
  }
  const auto signed_region = bytes.first(kWireHeaderBytes + payload_length);
  const Digest expected_tag = domain_digest(kWireIntegrityDomain, signed_region);
  if (!std::equal(expected_tag.bytes().begin(), expected_tag.bytes().end(),
                  bytes.begin() + static_cast<std::ptrdiff_t>(expected_size - kWireTagBytes))) {
    return WireDefect::INTEGRITY_FAILURE;
  }
  out.message = static_cast<WireMessageId>(raw_message);
  out.epoch = CoordinatorEpoch::from_value(epoch);
  out.publisher = PublisherId::from_bytes(publisher);
  out.worker_boot = WorkerBootId::from_bytes(worker_boot);
  out.attempt = MutationAttemptId::from_bytes(attempt);
  out.payload.assign(bytes.begin() + static_cast<std::ptrdiff_t>(kWireHeaderBytes),
                     bytes.begin() + static_cast<std::ptrdiff_t>(kWireHeaderBytes + payload_length));
  return WireDefect::NONE;
}

// --- shared value codecs ----------------------------------------------------

void encode_cost_claim(Encoder& encoder, const CostClaim& claim) {
  encoder.raw(claim.cost_class.bytes());
  encoder.raw(claim.binding.model.bytes());
  encoder.u32(claim.binding.model_version);
  encoder.raw(claim.binding.route_class.bytes());
  encoder.u64(claim.binding.policy_generation.value());
  encoder.i64(claim.cost.units);
  encoder.u32(claim.cost.scale);
  encoder.raw(claim.source.bytes());
}

bool decode_cost_claim(Decoder& decoder, CostClaim& out) {
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.cost_class = CostClassId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.binding.model = CostModelId::from_bytes(raw);
  if (!decoder.u32(out.binding.model_version)) {
    return false;
  }
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.binding.route_class = RouteClassId::from_bytes(raw);
  std::uint64_t policy = 0;
  if (!decoder.u64(policy)) {
    return false;
  }
  out.binding.policy_generation = CostPolicyGeneration::from_value(policy);
  if (!decoder.i64(out.cost.units)) {
    return false;
  }
  if (!decoder.u32(out.cost.scale)) {
    return false;
  }
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.source = ProvenanceId::from_bytes(raw);
  return true;
}

void encode_group_key(Encoder& encoder, const GroupKey& key) {
  encoder.raw(key.fabric.bytes());
  encoder.raw(key.routing_namespace.bytes());
  encoder.raw(key.destination.bytes());
  encoder.raw(key.cost_class.bytes());
}

bool decode_group_key(Decoder& decoder, GroupKey& out) {
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.fabric = FabricId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.routing_namespace = RoutingNamespaceId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.destination = DestinationId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.cost_class = CostClassId::from_bytes(raw);
  return true;
}

void encode_member_spec(Encoder& encoder, const MemberSpec& spec) {
  encoder.raw(spec.member.bytes());
  encoder.raw(spec.path.bytes());
  encoder.u64(spec.path_authority.value());
  encoder.u64(spec.member_generation.value());
  encode_cost_claim(encoder, spec.cost);
  encoder.raw(spec.provenance.bytes());
  encoder.boolean(spec.administratively_enabled);
}

bool decode_member_spec(Decoder& decoder, const GovernorLimits& limits, MemberSpec& out) {
  (void)limits;
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.member = ECMPMemberId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.path = PathId::from_bytes(raw);
  std::uint64_t generation = 0;
  if (!decoder.u64(generation)) {
    return false;
  }
  out.path_authority = PathAuthorityGeneration::from_value(generation);
  if (!decoder.u64(generation)) {
    return false;
  }
  out.member_generation = MemberGeneration::from_value(generation);
  if (!decode_cost_claim(decoder, out.cost)) {
    return false;
  }
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.provenance = ProvenanceId::from_bytes(raw);
  return decoder.boolean(out.administratively_enabled);
}

void encode_member_record(Encoder& encoder, const MemberRecord& record) {
  encoder.raw(record.member.bytes());
  encoder.raw(record.path.bytes());
  encoder.u64(record.path_authority.value());
  encoder.u64(record.member_generation.value());
  encode_cost_claim(encoder, record.cost);
  encoder.raw(record.provenance.bytes());
  encoder.boolean(record.administratively_enabled);
  encoder.boolean(record.declared);
  encoder.u8(static_cast<std::uint8_t>(record.state));
}

bool decode_member_record(Decoder& decoder, const GovernorLimits& limits, MemberRecord& out) {
  (void)limits;
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.member = ECMPMemberId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.path = PathId::from_bytes(raw);
  std::uint64_t generation = 0;
  if (!decoder.u64(generation)) {
    return false;
  }
  out.path_authority = PathAuthorityGeneration::from_value(generation);
  if (!decoder.u64(generation)) {
    return false;
  }
  out.member_generation = MemberGeneration::from_value(generation);
  if (!decode_cost_claim(decoder, out.cost)) {
    return false;
  }
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.provenance = ProvenanceId::from_bytes(raw);
  if (!decoder.boolean(out.administratively_enabled)) {
    return false;
  }
  if (!decoder.boolean(out.declared)) {
    return false;
  }
  return decode_state(decoder, out.state);
}

void encode_bucket_assignment(Encoder& encoder, const BucketAssignment& assignment) {
  encoder.u32(assignment.count.value());
  encoder.u32(static_cast<std::uint32_t>(assignment.owners.size()));
  for (const ECMPMemberId& owner : assignment.owners) {
    encoder.raw(owner.bytes());
  }
}

bool decode_bucket_assignment(Decoder& decoder, const GovernorLimits& limits,
                              BucketAssignment& out) {
  std::uint32_t count = 0;
  std::uint32_t owners = 0;
  if (!decoder.u32(count) || !decoder.u32(owners)) {
    return false;
  }
  if (count == 0 || count > limits.max_buckets || owners != count) {
    return false;
  }
  const auto bucket_count = BucketCount::make(count);
  if (!bucket_count.has_value()) {
    return false;
  }
  out.count = *bucket_count;
  out.owners.clear();
  out.owners.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    std::array<std::uint8_t, 16> raw{};
    if (!decoder.fixed16(raw)) {
      return false;
    }
    out.owners.push_back(ECMPMemberId::from_bytes(raw));
  }
  return true;
}

void encode_condition_list(Encoder& encoder, const ConditionList& conditions) {
  encoder.u32(static_cast<std::uint32_t>(conditions.entries().size()));
  for (const Condition& condition : conditions.entries()) {
    encoder.u32(static_cast<std::uint32_t>(condition.code));
    encoder.text(condition.subject);
    encoder.u64(condition.observed);
    encoder.u64(condition.expected);
  }
  encoder.boolean(conditions.truncated());
}

bool decode_condition_list(Decoder& decoder, const GovernorLimits& limits, ConditionList& out) {
  std::uint32_t count = 0;
  if (!decoder.u32(count)) {
    return false;
  }
  if (count > limits.max_explanation_entries) {
    return false;
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    std::uint32_t code = 0;
    std::string subject;
    std::uint64_t observed = 0;
    std::uint64_t expected = 0;
    if (!decoder.u32(code) || !decoder.text(subject, kMaxSubjectBytes) ||
        !decoder.u64(observed) || !decoder.u64(expected)) {
      return false;
    }
    Condition condition;
    condition.code = static_cast<ConditionCode>(code);
    condition.subject = std::move(subject);
    condition.observed = observed;
    condition.expected = expected;
    out.add(std::move(condition));
  }
  bool truncated = false;
  if (!decoder.boolean(truncated)) {
    return false;
  }
  (void)truncated;
  return true;
}

void encode_bucket_move(Encoder& encoder, const BucketMove& move) {
  encoder.u32(move.bucket.value());
  encoder.raw(move.from.bytes());
  encoder.raw(move.to.bytes());
  encode_move_reason(encoder, move.reason);
}

bool decode_bucket_move(Decoder& decoder, BucketMove& out) {
  std::uint32_t bucket = 0;
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.u32(bucket)) {
    return false;
  }
  out.bucket = BucketId::from_value(bucket);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.from = ECMPMemberId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.to = ECMPMemberId::from_bytes(raw);
  return decode_move_reason(decoder, out.reason);
}

void encode_rebalance_record(Encoder& encoder, const RebalanceRecord& record) {
  encoder.raw(record.plan.bytes());
  encode_change_reason(encoder, record.reason);
  encoder.u64(record.from_membership.value());
  encoder.u64(record.to_membership.value());
  encoder.u64(record.from_assignment.value());
  encoder.u64(record.to_assignment.value());
  encoder.u32(static_cast<std::uint32_t>(record.moves.size()));
  for (const BucketMove& move : record.moves) {
    encode_bucket_move(encoder, move);
  }
  encoder.u64(record.churn);
  encoder.raw(record.assignment_digest.bytes());
}

bool decode_rebalance_record(Decoder& decoder, const GovernorLimits& limits,
                             RebalanceRecord& out) {
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.plan = RebalancePlanId::from_bytes(raw);
  if (!decode_change_reason(decoder, out.reason)) {
    return false;
  }
  std::uint64_t value = 0;
  if (!decoder.u64(value)) {
    return false;
  }
  out.from_membership = MembershipGeneration::from_value(value);
  if (!decoder.u64(value)) {
    return false;
  }
  out.to_membership = MembershipGeneration::from_value(value);
  if (!decoder.u64(value)) {
    return false;
  }
  out.from_assignment = AssignmentGeneration::from_value(value);
  if (!decoder.u64(value)) {
    return false;
  }
  out.to_assignment = AssignmentGeneration::from_value(value);
  std::uint32_t move_count = 0;
  if (!decoder.u32(move_count)) {
    return false;
  }
  if (move_count > limits.max_buckets) {
    return false;
  }
  out.moves.clear();
  out.moves.reserve(move_count);
  for (std::uint32_t index = 0; index < move_count; ++index) {
    BucketMove move;
    if (!decode_bucket_move(decoder, move)) {
      return false;
    }
    out.moves.push_back(move);
  }
  if (!decoder.u64(out.churn)) {
    return false;
  }
  std::array<std::uint8_t, 32> digest{};
  if (!decoder.raw(digest)) {
    return false;
  }
  out.assignment_digest = Digest::from_bytes(digest);
  return true;
}

void encode_group_summary(Encoder& encoder, const GroupSummary& summary) {
  encoder.raw(summary.id.bytes());
  encode_group_key(encoder, summary.key);
  encoder.u8(static_cast<std::uint8_t>(summary.source));
  encoder.u8(static_cast<std::uint8_t>(summary.lifecycle));
  encoder.u32(summary.currentness.bits());
  encoder.u64(summary.membership_generation.value());
  encoder.u64(summary.assignment_generation.value());
  encoder.u64(summary.authority_generation.value());
  encoder.u32(summary.declared_members);
  encoder.u32(summary.active_members);
  encoder.u32(summary.min_active_members);
  encoder.u32(summary.bucket_count.value());
  encoder.raw(summary.membership_digest.bytes());
  encoder.raw(summary.assignment_digest.bytes());
  encoder.raw(summary.semantic_digest.bytes());
}

bool decode_group_summary(Decoder& decoder, const GovernorLimits& limits, GroupSummary& out) {
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.id = ECMPGroupId::from_bytes(raw);
  if (!decode_group_key(decoder, out.key)) {
    return false;
  }
  if (!decode_source(decoder, out.source) || !decode_lifecycle(decoder, out.lifecycle)) {
    return false;
  }
  std::uint32_t bits = 0;
  if (!decoder.u32(bits)) {
    return false;
  }
  out.currentness = Currentness::from_bits(bits);
  std::uint64_t value = 0;
  if (!decoder.u64(value)) {
    return false;
  }
  out.membership_generation = MembershipGeneration::from_value(value);
  if (!decoder.u64(value)) {
    return false;
  }
  out.assignment_generation = AssignmentGeneration::from_value(value);
  if (!decoder.u64(value)) {
    return false;
  }
  out.authority_generation = AuthorityGeneration::from_value(value);
  if (!decoder.u32(out.declared_members) || !decoder.u32(out.active_members) ||
      !decoder.u32(out.min_active_members)) {
    return false;
  }
  std::uint32_t buckets = 0;
  if (!decoder.u32(buckets)) {
    return false;
  }
  const auto bucket_count = BucketCount::make(buckets);
  if (!bucket_count.has_value() || buckets > limits.max_buckets) {
    return false;
  }
  out.bucket_count = *bucket_count;
  std::array<std::uint8_t, 32> digest{};
  if (!decoder.raw(digest)) {
    return false;
  }
  out.membership_digest = Digest::from_bytes(digest);
  if (!decoder.raw(digest)) {
    return false;
  }
  out.assignment_digest = Digest::from_bytes(digest);
  if (!decoder.raw(digest)) {
    return false;
  }
  out.semantic_digest = Digest::from_bytes(digest);
  return true;
}

void encode_group_snapshot(Encoder& encoder, const GroupSnapshot& snapshot) {
  encoder.raw(snapshot.id.bytes());
  encode_group_key(encoder, snapshot.key);
  encoder.u8(static_cast<std::uint8_t>(snapshot.source));
  encoder.u8(static_cast<std::uint8_t>(snapshot.lifecycle));
  encoder.u32(snapshot.currentness.bits());
  encoder.u64(snapshot.membership_generation.value());
  encoder.u64(snapshot.assignment_generation.value());
  encoder.u64(snapshot.authority_generation.value());
  encoder.raw(snapshot.cost_semantics.cost_class.bytes());
  encoder.raw(snapshot.cost_semantics.binding.model.bytes());
  encoder.u32(snapshot.cost_semantics.binding.model_version);
  encoder.raw(snapshot.cost_semantics.binding.route_class.bytes());
  encoder.u64(snapshot.cost_semantics.binding.policy_generation.value());
  encoder.i64(snapshot.canonical_cost.units);
  encoder.u32(snapshot.canonical_cost.scale);
  encoder.raw(snapshot.hash_domain.bytes());
  encoder.u32(snapshot.bucket_count.value());
  encoder.u32(snapshot.min_active_members);
  encoder.u32(static_cast<std::uint32_t>(snapshot.members.size()));
  for (const MemberRecord& record : snapshot.members) {
    encode_member_record(encoder, record);
  }
  encoder.u32(static_cast<std::uint32_t>(snapshot.active_members.size()));
  for (const ECMPMemberId& member : snapshot.active_members) {
    encoder.raw(member.bytes());
  }
  encode_bucket_assignment(encoder, snapshot.assignment);
  encoder.raw(snapshot.multipath_set.bytes());
  encoder.u64(snapshot.multipath_generation.value());
  encoder.u64(snapshot.epoch.value());
  encoder.raw(snapshot.authority_publisher.bytes());
  encoder.raw(snapshot.provenance.bytes());
  encoder.raw(snapshot.membership_digest.bytes());
  encoder.raw(snapshot.assignment_digest.bytes());
  encoder.raw(snapshot.semantic_digest.bytes());
  encoder.boolean(snapshot.pending_plan.has_value());
  if (snapshot.pending_plan.has_value()) {
    encoder.raw(snapshot.pending_plan->bytes());
  }
}

bool decode_group_snapshot(Decoder& decoder, const GovernorLimits& limits, GroupSnapshot& out) {
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.id = ECMPGroupId::from_bytes(raw);
  if (!decode_group_key(decoder, out.key) || !decode_source(decoder, out.source) ||
      !decode_lifecycle(decoder, out.lifecycle)) {
    return false;
  }
  std::uint32_t bits = 0;
  if (!decoder.u32(bits)) {
    return false;
  }
  out.currentness = Currentness::from_bits(bits);
  std::uint64_t value = 0;
  if (!decoder.u64(value)) {
    return false;
  }
  out.membership_generation = MembershipGeneration::from_value(value);
  if (!decoder.u64(value)) {
    return false;
  }
  out.assignment_generation = AssignmentGeneration::from_value(value);
  if (!decoder.u64(value)) {
    return false;
  }
  out.authority_generation = AuthorityGeneration::from_value(value);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.cost_semantics.cost_class = CostClassId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.cost_semantics.binding.model = CostModelId::from_bytes(raw);
  if (!decoder.u32(out.cost_semantics.binding.model_version)) {
    return false;
  }
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.cost_semantics.binding.route_class = RouteClassId::from_bytes(raw);
  if (!decoder.u64(value)) {
    return false;
  }
  out.cost_semantics.binding.policy_generation = CostPolicyGeneration::from_value(value);
  if (!decoder.i64(out.canonical_cost.units) || !decoder.u32(out.canonical_cost.scale)) {
    return false;
  }
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.hash_domain = HashDomainId::from_bytes(raw);
  std::uint32_t buckets = 0;
  if (!decoder.u32(buckets)) {
    return false;
  }
  const auto bucket_count = BucketCount::make(buckets);
  if (!bucket_count.has_value() || buckets > limits.max_buckets) {
    return false;
  }
  out.bucket_count = *bucket_count;
  if (!decoder.u32(out.min_active_members)) {
    return false;
  }
  if (out.min_active_members == 0 || out.min_active_members > limits.max_members_per_group) {
    return false;
  }
  std::uint32_t member_count = 0;
  if (!decoder.u32(member_count)) {
    return false;
  }
  if (member_count > limits.max_members_per_group) {
    return false;
  }
  out.members.clear();
  out.members.reserve(member_count);
  for (std::uint32_t index = 0; index < member_count; ++index) {
    MemberRecord record;
    if (!decode_member_record(decoder, limits, record)) {
      return false;
    }
    out.members.push_back(std::move(record));
  }
  std::uint32_t active_count = 0;
  if (!decoder.u32(active_count)) {
    return false;
  }
  if (active_count > limits.max_members_per_group) {
    return false;
  }
  out.active_members.clear();
  out.active_members.reserve(active_count);
  for (std::uint32_t index = 0; index < active_count; ++index) {
    if (!decoder.fixed16(raw)) {
      return false;
    }
    out.active_members.push_back(ECMPMemberId::from_bytes(raw));
  }
  if (!decode_bucket_assignment(decoder, limits, out.assignment)) {
    return false;
  }
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.multipath_set = MultipathSetId::from_bytes(raw);
  if (!decoder.u64(value)) {
    return false;
  }
  out.multipath_generation = MultipathSetGeneration::from_value(value);
  if (!decoder.u64(value)) {
    return false;
  }
  out.epoch = CoordinatorEpoch::from_value(value);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.authority_publisher = PublisherId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.provenance = ProvenanceId::from_bytes(raw);
  std::array<std::uint8_t, 32> digest{};
  if (!decoder.raw(digest)) {
    return false;
  }
  out.membership_digest = Digest::from_bytes(digest);
  if (!decoder.raw(digest)) {
    return false;
  }
  out.assignment_digest = Digest::from_bytes(digest);
  if (!decoder.raw(digest)) {
    return false;
  }
  out.semantic_digest = Digest::from_bytes(digest);
  bool has_plan = false;
  if (!decoder.boolean(has_plan)) {
    return false;
  }
  if (has_plan) {
    RebalancePlanId plan;
    if (!decode_plan_id(decoder, plan)) {
      return false;
    }
    out.pending_plan = plan;
  }
  return true;
}

void encode_mutation_result(Encoder& encoder, const MutationResult& result) {
  encoder.u32(static_cast<std::uint32_t>(result.outcome));
  encode_condition_list(encoder, result.conditions);
  encoder.text(result.detail);
  encoder.boolean(result.group.has_value());
  if (result.group.has_value()) {
    encode_group_summary(encoder, *result.group);
  }
  encoder.boolean(result.plan.has_value());
  if (result.plan.has_value()) {
    encoder.raw(result.plan->bytes());
  }
}

bool decode_mutation_result(Decoder& decoder, const GovernorLimits& limits, MutationResult& out) {
  std::uint32_t outcome = 0;
  if (!decoder.u32(outcome)) {
    return false;
  }
  out.outcome = static_cast<Outcome>(outcome);
  ConditionList conditions(limits.max_explanation_entries);
  if (!decode_condition_list(decoder, limits, conditions)) {
    return false;
  }
  out.conditions = conditions;
  if (!decoder.text(out.detail, kMaxTextBytes)) {
    return false;
  }
  bool has_group = false;
  if (!decoder.boolean(has_group)) {
    return false;
  }
  if (has_group) {
    GroupSummary summary;
    if (!decode_group_summary(decoder, limits, summary)) {
      return false;
    }
    out.group = summary;
  }
  bool has_plan = false;
  if (!decoder.boolean(has_plan)) {
    return false;
  }
  if (has_plan) {
    RebalancePlanId plan;
    if (!decode_plan_id(decoder, plan)) {
      return false;
    }
    out.plan = plan;
  }
  return true;
}

std::vector<std::uint8_t> encode_mutation_result(const MutationResult& result) {
  Encoder encoder;
  encode_mutation_result(encoder, result);
  return encoder.take();
}

bool decode_mutation_result(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                            MutationResult& out) {
  Decoder decoder(bytes, limits.max_frame_bytes);
  if (!decode_mutation_result(decoder, limits, out)) {
    return false;
  }
  return decoder.at_end();
}

// --- request payloads -------------------------------------------------------

std::vector<std::uint8_t> encode_payload(const ExplainRequest& request) {
  Encoder encoder;
  encoder.raw(request.group.bytes());
  encoder.u32(static_cast<std::uint32_t>(request.kind));
  encoder.raw(request.member.bytes());
  encoder.u32(request.bucket.value());
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                    ExplainRequest& out) {
  Decoder decoder(bytes, limits.max_frame_bytes);
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.group = ECMPGroupId::from_bytes(raw);
  std::uint32_t kind = 0;
  if (!decoder.u32(kind) || kind < 1 || kind > 5) {
    return false;
  }
  out.kind = static_cast<ExplainKind>(kind);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.member = ECMPMemberId::from_bytes(raw);
  std::uint32_t bucket = 0;
  if (!decoder.u32(bucket)) {
    return false;
  }
  out.bucket = BucketId::from_value(bucket);
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_explain_response(const ExplainResponseBody& body) {
  Encoder encoder;
  encoder.boolean(body.found);
  encoder.text(body.text);
  return encoder.take();
}

bool decode_explain_response(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                             ExplainResponseBody& out) {
  Decoder decoder(bytes, limits.max_frame_bytes);
  if (!decoder.boolean(out.found)) {
    return false;
  }
  if (!decoder.text(out.text, 65536)) {
    return false;
  }
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const PublisherRegistration& registration) {
  Encoder encoder;
  encoder.raw(registration.publisher.bytes());
  encoder.raw(registration.worker_boot.bytes());
  encoder.u8(static_cast<std::uint8_t>(registration.scope.kind));
  encoder.raw(registration.scope.fabric.bytes());
  encoder.raw(registration.scope.routing_namespace.bytes());
  encoder.raw(registration.scope.destination.bytes());
  encoder.raw(registration.scope.group.bytes());
  encoder.u32(registration.capabilities);
  encoder.raw(registration.provenance.bytes());
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                    PublisherRegistration& out) {
  Decoder decoder(bytes, limits.max_frame_bytes);
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.publisher = PublisherId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.worker_boot = WorkerBootId::from_bytes(raw);
  if (!decode_scope_kind(decoder, out.scope.kind)) {
    return false;
  }
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.scope.fabric = FabricId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.scope.routing_namespace = RoutingNamespaceId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.scope.destination = DestinationId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.scope.group = ECMPGroupId::from_bytes(raw);
  if (!decoder.u32(out.capabilities)) {
    return false;
  }
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.provenance = ProvenanceId::from_bytes(raw);
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const ECMPGroupId& group) {
  Encoder encoder;
  encoder.raw(group.bytes());
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                    ECMPGroupId& out) {
  Decoder decoder(bytes, limits.max_frame_bytes);
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out = ECMPGroupId::from_bytes(raw);
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const CreateGroupRequest& request) {
  Encoder encoder;
  encoder.raw(request.group.bytes());
  encode_group_key(encoder, request.key);
  encoder.u8(static_cast<std::uint8_t>(request.source));
  encoder.raw(request.multipath_set.bytes());
  encoder.u64(request.multipath_generation.value());
  encoder.raw(request.cost_semantics.cost_class.bytes());
  encoder.raw(request.cost_semantics.binding.model.bytes());
  encoder.u32(request.cost_semantics.binding.model_version);
  encoder.raw(request.cost_semantics.binding.route_class.bytes());
  encoder.u64(request.cost_semantics.binding.policy_generation.value());
  encoder.raw(request.hash_domain.bytes());
  encoder.u32(request.bucket_count.value());
  encoder.u32(request.min_active_members);
  encoder.raw(request.provenance.bytes());
  encoder.u32(static_cast<std::uint32_t>(request.members.size()));
  for (const MemberSpec& spec : request.members) {
    encode_member_spec(encoder, spec);
  }
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                    CreateGroupRequest& out) {
  Decoder decoder(bytes, limits.max_frame_bytes);
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.group = ECMPGroupId::from_bytes(raw);
  if (!decode_group_key(decoder, out.key) || !decode_source(decoder, out.source)) {
    return false;
  }
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.multipath_set = MultipathSetId::from_bytes(raw);
  std::uint64_t value = 0;
  if (!decoder.u64(value)) {
    return false;
  }
  out.multipath_generation = MultipathSetGeneration::from_value(value);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.cost_semantics.cost_class = CostClassId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.cost_semantics.binding.model = CostModelId::from_bytes(raw);
  if (!decoder.u32(out.cost_semantics.binding.model_version)) {
    return false;
  }
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.cost_semantics.binding.route_class = RouteClassId::from_bytes(raw);
  if (!decoder.u64(value)) {
    return false;
  }
  out.cost_semantics.binding.policy_generation = CostPolicyGeneration::from_value(value);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.hash_domain = HashDomainId::from_bytes(raw);
  std::uint32_t buckets = 0;
  if (!decoder.u32(buckets)) {
    return false;
  }
  const auto bucket_count = BucketCount::make(buckets);
  if (!bucket_count.has_value()) {
    return false;
  }
  out.bucket_count = *bucket_count;
  if (!decoder.u32(out.min_active_members)) {
    return false;
  }
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.provenance = ProvenanceId::from_bytes(raw);
  std::uint32_t member_count = 0;
  if (!decoder.u32(member_count)) {
    return false;
  }
  if (member_count > limits.max_members_per_group) {
    return false;
  }
  out.members.clear();
  out.members.reserve(member_count);
  for (std::uint32_t index = 0; index < member_count; ++index) {
    MemberSpec spec;
    if (!decode_member_spec(decoder, limits, spec)) {
      return false;
    }
    out.members.push_back(std::move(spec));
  }
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const AddMemberRequest& request) {
  Encoder encoder;
  encoder.raw(request.group.bytes());
  encode_member_spec(encoder, request.member);
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                    AddMemberRequest& out) {
  Decoder decoder(bytes, limits.max_frame_bytes);
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.group = ECMPGroupId::from_bytes(raw);
  if (!decode_member_spec(decoder, limits, out.member)) {
    return false;
  }
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const RemoveMemberRequest& request) {
  Encoder encoder;
  encoder.raw(request.group.bytes());
  encoder.raw(request.member.bytes());
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                    RemoveMemberRequest& out) {
  Decoder decoder(bytes, limits.max_frame_bytes);
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.group = ECMPGroupId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.member = ECMPMemberId::from_bytes(raw);
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const SetMemberEnabledRequest& request) {
  Encoder encoder;
  encoder.raw(request.group.bytes());
  encoder.raw(request.member.bytes());
  encoder.boolean(request.enabled);
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                    SetMemberEnabledRequest& out) {
  Decoder decoder(bytes, limits.max_frame_bytes);
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.group = ECMPGroupId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.member = ECMPMemberId::from_bytes(raw);
  if (!decoder.boolean(out.enabled)) {
    return false;
  }
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const MembershipSetRequest& request) {
  Encoder encoder;
  encoder.raw(request.group.bytes());
  encoder.u32(static_cast<std::uint32_t>(request.members.size()));
  for (const MemberSpec& spec : request.members) {
    encode_member_spec(encoder, spec);
  }
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                    MembershipSetRequest& out) {
  Decoder decoder(bytes, limits.max_frame_bytes);
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.group = ECMPGroupId::from_bytes(raw);
  std::uint32_t count = 0;
  if (!decoder.u32(count)) {
    return false;
  }
  if (count > limits.max_members_per_group) {
    return false;
  }
  out.members.clear();
  out.members.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    MemberSpec spec;
    if (!decode_member_spec(decoder, limits, spec)) {
      return false;
    }
    out.members.push_back(std::move(spec));
  }
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const RevalidateGroupRequest& request) {
  Encoder encoder;
  encoder.raw(request.group.bytes());
  encoder.u32(static_cast<std::uint32_t>(request.members.size()));
  for (const MemberRevalidation& update : request.members) {
    encoder.raw(update.member.bytes());
    encoder.u64(update.path_authority.value());
    encoder.boolean(update.cost.has_value());
    if (update.cost.has_value()) {
      encode_cost_claim(encoder, *update.cost);
    }
  }
  encoder.boolean(request.multipath_generation.has_value());
  if (request.multipath_generation.has_value()) {
    encoder.u64(request.multipath_generation->value());
  }
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                    RevalidateGroupRequest& out) {
  Decoder decoder(bytes, limits.max_frame_bytes);
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.group = ECMPGroupId::from_bytes(raw);
  std::uint32_t count = 0;
  if (!decoder.u32(count)) {
    return false;
  }
  if (count > limits.max_batch_size) {
    return false;
  }
  out.members.clear();
  out.members.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    MemberRevalidation update;
    if (!decoder.fixed16(raw)) {
      return false;
    }
    update.member = ECMPMemberId::from_bytes(raw);
    std::uint64_t generation = 0;
    if (!decoder.u64(generation)) {
      return false;
    }
    update.path_authority = PathAuthorityGeneration::from_value(generation);
    bool has_cost = false;
    if (!decoder.boolean(has_cost)) {
      return false;
    }
    if (has_cost) {
      CostClaim claim;
      if (!decode_cost_claim(decoder, claim)) {
        return false;
      }
      update.cost = claim;
    }
    out.members.push_back(std::move(update));
  }
  bool has_multipath = false;
  if (!decoder.boolean(has_multipath)) {
    return false;
  }
  if (has_multipath) {
    std::uint64_t generation = 0;
    if (!decoder.u64(generation)) {
      return false;
    }
    out.multipath_generation = MultipathSetGeneration::from_value(generation);
  }
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const RebalancePlanRequest& request) {
  Encoder encoder;
  encoder.raw(request.group.bytes());
  encoder.u32(static_cast<std::uint32_t>(request.target_members.size()));
  for (const MemberSpec& spec : request.target_members) {
    encode_member_spec(encoder, spec);
  }
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                    RebalancePlanRequest& out) {
  Decoder decoder(bytes, limits.max_frame_bytes);
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.group = ECMPGroupId::from_bytes(raw);
  std::uint32_t count = 0;
  if (!decoder.u32(count)) {
    return false;
  }
  if (count > limits.max_members_per_group) {
    return false;
  }
  out.target_members.clear();
  out.target_members.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    MemberSpec spec;
    if (!decode_member_spec(decoder, limits, spec)) {
      return false;
    }
    out.target_members.push_back(std::move(spec));
  }
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const RebalanceCommitRequest& request) {
  Encoder encoder;
  encoder.raw(request.group.bytes());
  encoder.raw(request.plan.bytes());
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                    RebalanceCommitRequest& out) {
  Decoder decoder(bytes, limits.max_frame_bytes);
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.group = ECMPGroupId::from_bytes(raw);
  if (!decode_plan_id(decoder, out.plan)) {
    return false;
  }
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const RebalanceAbortRequest& request) {
  Encoder encoder;
  encoder.raw(request.group.bytes());
  encoder.raw(request.plan.bytes());
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                    RebalanceAbortRequest& out) {
  Decoder decoder(bytes, limits.max_frame_bytes);
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.group = ECMPGroupId::from_bytes(raw);
  if (!decode_plan_id(decoder, out.plan)) {
    return false;
  }
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const GroupAdminRequest& request) {
  Encoder encoder;
  encoder.raw(request.group.bytes());
  encoder.raw(request.successor.bytes());
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                    GroupAdminRequest& out) {
  Decoder decoder(bytes, limits.max_frame_bytes);
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.group = ECMPGroupId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.successor = ECMPGroupId::from_bytes(raw);
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const PathAuthorityChangeNotice& notice) {
  Encoder encoder;
  encoder.raw(notice.path.bytes());
  encoder.u64(notice.generation.value());
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                    PathAuthorityChangeNotice& out) {
  Decoder decoder(bytes, limits.max_frame_bytes);
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.path = PathId::from_bytes(raw);
  std::uint64_t generation = 0;
  if (!decoder.u64(generation)) {
    return false;
  }
  out.generation = PathAuthorityGeneration::from_value(generation);
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const MultipathSetChangeNotice& notice) {
  Encoder encoder;
  encoder.raw(notice.set.bytes());
  encoder.u64(notice.generation.value());
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                    MultipathSetChangeNotice& out) {
  Decoder decoder(bytes, limits.max_frame_bytes);
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.set = MultipathSetId::from_bytes(raw);
  std::uint64_t generation = 0;
  if (!decoder.u64(generation)) {
    return false;
  }
  out.generation = MultipathSetGeneration::from_value(generation);
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_payload(const CostGenerationChangeNotice& notice) {
  Encoder encoder;
  encoder.raw(notice.cost_class.bytes());
  encoder.u64(notice.generation.value());
  return encoder.take();
}

bool decode_payload(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                    CostGenerationChangeNotice& out) {
  Decoder decoder(bytes, limits.max_frame_bytes);
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.cost_class = CostClassId::from_bytes(raw);
  std::uint64_t generation = 0;
  if (!decoder.u64(generation)) {
    return false;
  }
  out.generation = CostPolicyGeneration::from_value(generation);
  return decoder.at_end();
}

// --- response payloads ------------------------------------------------------

std::vector<std::uint8_t> encode_hello_response(const HelloResponseBody& body) {
  Encoder encoder;
  encoder.u32(body.wire_version);
  encoder.u64(body.epoch.value());
  encoder.text(body.product);
  encoder.text(body.version);
  return encoder.take();
}

bool decode_hello_response(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                           HelloResponseBody& out) {
  Decoder decoder(bytes, limits.max_frame_bytes);
  if (!decoder.u32(out.wire_version)) {
    return false;
  }
  std::uint64_t epoch = 0;
  if (!decoder.u64(epoch)) {
    return false;
  }
  out.epoch = CoordinatorEpoch::from_value(epoch);
  if (!decoder.text(out.product, kMaxTextBytes) || !decoder.text(out.version, kMaxTextBytes)) {
    return false;
  }
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_register_publisher_response(
    const RegisterPublisherResponseBody& body) {
  Encoder encoder;
  encoder.u32(static_cast<std::uint32_t>(body.outcome));
  encode_condition_list(encoder, body.conditions);
  return encoder.take();
}

bool decode_register_publisher_response(std::span<const std::uint8_t> bytes,
                                        const GovernorLimits& limits,
                                        RegisterPublisherResponseBody& out) {
  Decoder decoder(bytes, limits.max_frame_bytes);
  std::uint32_t outcome = 0;
  if (!decoder.u32(outcome)) {
    return false;
  }
  out.outcome = static_cast<Outcome>(outcome);
  ConditionList conditions(limits.max_explanation_entries);
  if (!decode_condition_list(decoder, limits, conditions)) {
    return false;
  }
  out.conditions = conditions;
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_snapshot_response(const SnapshotResponseBody& body) {
  Encoder encoder;
  encoder.boolean(body.found);
  if (body.found) {
    encode_group_snapshot(encoder, body.snapshot);
  }
  return encoder.take();
}

bool decode_snapshot_response(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                              SnapshotResponseBody& out) {
  Decoder decoder(bytes, limits.max_frame_bytes);
  if (!decoder.boolean(out.found)) {
    return false;
  }
  if (out.found && !decode_group_snapshot(decoder, limits, out.snapshot)) {
    return false;
  }
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_group_query_response(const GroupQueryResponseBody& body) {
  Encoder encoder;
  encoder.boolean(body.found);
  if (body.found) {
    encode_group_summary(encoder, body.summary);
  }
  return encoder.take();
}

bool decode_group_query_response(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                                 GroupQueryResponseBody& out) {
  Decoder decoder(bytes, limits.max_frame_bytes);
  if (!decoder.boolean(out.found)) {
    return false;
  }
  if (out.found && !decode_group_summary(decoder, limits, out.summary)) {
    return false;
  }
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_list_groups_response(const ListGroupsResponseBody& body) {
  Encoder encoder;
  encoder.u32(static_cast<std::uint32_t>(body.groups.size()));
  for (const GroupSummary& summary : body.groups) {
    encode_group_summary(encoder, summary);
  }
  return encoder.take();
}

bool decode_list_groups_response(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                                 ListGroupsResponseBody& out) {
  Decoder decoder(bytes, limits.max_frame_bytes);
  std::uint32_t count = 0;
  if (!decoder.u32(count)) {
    return false;
  }
  if (count > limits.max_groups) {
    return false;
  }
  out.groups.clear();
  out.groups.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    GroupSummary summary;
    if (!decode_group_summary(decoder, limits, summary)) {
      return false;
    }
    out.groups.push_back(std::move(summary));
  }
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_rebalance_result(const RebalanceResultBody& body) {
  Encoder encoder;
  encode_mutation_result(encoder, body.result);
  encode_rebalance_record(encoder, body.record);
  return encoder.take();
}

bool decode_rebalance_result(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                             RebalanceResultBody& out) {
  Decoder decoder(bytes, limits.max_frame_bytes);
  if (!decode_mutation_result(decoder, limits, out.result)) {
    return false;
  }
  if (!decode_rebalance_record(decoder, limits, out.record)) {
    return false;
  }
  return decoder.at_end();
}

std::vector<std::uint8_t> encode_error_body(const ErrorBody& body) {
  Encoder encoder;
  encoder.u32(static_cast<std::uint32_t>(body.code));
  encoder.u32(static_cast<std::uint32_t>(body.outcome));
  encoder.text(body.detail);
  return encoder.take();
}

bool decode_error_body(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                       ErrorBody& out) {
  Decoder decoder(bytes, limits.max_frame_bytes);
  std::uint32_t code = 0;
  std::uint32_t outcome = 0;
  if (!decoder.u32(code) || !decoder.u32(outcome)) {
    return false;
  }
  out.code = static_cast<ConditionCode>(code);
  out.outcome = static_cast<Outcome>(outcome);
  if (!decoder.text(out.detail, kMaxTextBytes)) {
    return false;
  }
  return decoder.at_end();
}

}  // namespace ecmp
