#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "ecmp/ecmp.hpp"
#include "test_framework.hpp"

namespace {

using namespace ecmp;

Envelope make_envelope(WireMessageId id, std::vector<std::uint8_t> payload = {}) {
  Envelope envelope;
  envelope.message = id;
  envelope.epoch = CoordinatorEpoch::from_value(9);
  envelope.publisher = synthetic_publisher_id(1);
  envelope.worker_boot = synthetic_boot_id(1);
  envelope.attempt = synthetic_attempt_id(1);
  envelope.payload = std::move(payload);
  return envelope;
}

}  // namespace

ECMP_TEST(test_wire_message_identifiers_are_stable) {
  ECMP_CHECK_EQ(static_cast<std::uint16_t>(WireMessageId::HELLO), std::uint16_t{0x0001});
  ECMP_CHECK_EQ(static_cast<std::uint16_t>(WireMessageId::CREATE_GROUP), std::uint16_t{0x0020});
  ECMP_CHECK_EQ(static_cast<std::uint16_t>(WireMessageId::SNAPSHOT_RESPONSE),
                std::uint16_t{0x0033});
  ECMP_CHECK_EQ(static_cast<std::uint16_t>(WireMessageId::FENCE_NOTICE), std::uint16_t{0x0036});
  ECMP_CHECK_EQ(static_cast<std::uint16_t>(WireMessageId::ERROR), std::uint16_t{0x0037});
  ECMP_CHECK(is_known_message(0x0020));
  ECMP_CHECK(!is_known_message(0x00FF));
  ECMP_CHECK(!is_known_message(0x0000));
  ECMP_CHECK(is_response(WireMessageId::ERROR));
  ECMP_CHECK(!is_response(WireMessageId::CREATE_GROUP));
}

ECMP_TEST(test_frame_round_trip_and_rejections) {
  GovernorLimits limits;
  const std::vector<std::uint8_t> payload{9, 8, 7, 6, 5};
  const Envelope envelope = make_envelope(WireMessageId::ADD_MEMBER, payload);
  const std::vector<std::uint8_t> frame = encode_frame(envelope, limits);
  ECMP_CHECK_EQ(frame.size(), kWireOverheadBytes + payload.size());

  Envelope decoded;
  ECMP_CHECK(decode_frame(frame, limits, decoded) == WireDefect::NONE);
  ECMP_CHECK(decoded.message == WireMessageId::ADD_MEMBER);
  ECMP_CHECK_EQ(decoded.epoch.value(), std::uint64_t{9});
  ECMP_CHECK(decoded.publisher == envelope.publisher);
  ECMP_CHECK(decoded.worker_boot == envelope.worker_boot);
  ECMP_CHECK(decoded.attempt == envelope.attempt);
  ECMP_CHECK(decoded.payload == payload);

  // Truncation at every point.
  for (std::size_t length = 0; length < frame.size(); ++length) {
    const std::vector<std::uint8_t> truncated(frame.begin(),
                                              frame.begin() + static_cast<std::ptrdiff_t>(length));
    Envelope ignored;
    ECMP_CHECK(decode_frame(truncated, limits, ignored) != WireDefect::NONE);
  }

  // Trailing bytes.
  {
    std::vector<std::uint8_t> trailing = frame;
    trailing.push_back(0);
    Envelope ignored;
    ECMP_CHECK(decode_frame(trailing, limits, ignored) == WireDefect::TRAILING_BYTES);
  }

  // Magic, version, reserved field, unknown message and integrity.
  {
    std::vector<std::uint8_t> bad = frame;
    bad[0] = 'X';
    Envelope ignored;
    ECMP_CHECK(decode_frame(bad, limits, ignored) == WireDefect::BAD_MAGIC);
  }
  {
    std::vector<std::uint8_t> bad = frame;
    bad[4] = 9;
    Envelope ignored;
    ECMP_CHECK(decode_frame(bad, limits, ignored) == WireDefect::VERSION_MISMATCH);
  }
  {
    std::vector<std::uint8_t> bad = frame;
    bad[6] = 0xEE;
    Envelope ignored;
    ECMP_CHECK(decode_frame(bad, limits, ignored) == WireDefect::UNKNOWN_MESSAGE);
  }
  {
    std::vector<std::uint8_t> bad = frame;
    bad[72] = 1;
    Envelope ignored;
    ECMP_CHECK(decode_frame(bad, limits, ignored) == WireDefect::RESERVED_NOT_ZERO);
  }
  {
    std::vector<std::uint8_t> bad = frame;
    bad[kWireHeaderBytes] ^= 0x01;
    Envelope ignored;
    ECMP_CHECK(decode_frame(bad, limits, ignored) == WireDefect::INTEGRITY_FAILURE);
  }
  // The integrity tag covers the semantic header as well as the payload.
  {
    std::vector<std::uint8_t> bad = frame;
    bad[24] ^= 0x01;  // inside the publisher identity
    Envelope ignored;
    ECMP_CHECK(decode_frame(bad, limits, ignored) == WireDefect::INTEGRITY_FAILURE);
  }

  // Oversized declared payload.
  {
    std::vector<std::uint8_t> bad = frame;
    bad[12] = 0xFF;
    bad[13] = 0xFF;
    bad[14] = 0xFF;
    bad[15] = 0x7F;
    Envelope ignored;
    ECMP_CHECK(decode_frame(bad, limits, ignored) == WireDefect::FRAME_TOO_LARGE);
  }

  // Encoding a frame larger than the bound yields no frame at all.
  Envelope huge = make_envelope(WireMessageId::ADD_MEMBER,
                               std::vector<std::uint8_t>(limits.max_frame_bytes + 1, 0));
  ECMP_CHECK(encode_frame(huge, limits).empty());
}

ECMP_TEST(test_request_payload_codecs_round_trip) {
  GovernorLimits limits;
  const SyntheticIds ids = synthetic_ids(1);
  const auto authority = [&]() {
    AuthorityContext context;
    context.epoch = CoordinatorEpoch::from_value(3);
    context.publisher = synthetic_publisher_id(1);
    context.worker_boot = synthetic_boot_id(1);
    context.scope = AuthorityScope::for_fabric(ids.fabric);
    context.attempt = synthetic_attempt_id(5);
    context.expected_membership = MembershipGeneration::from_value(2);
    return context;
  };

  {
    PublisherRegistration registration;
    registration.publisher = synthetic_publisher_id(1);
    registration.worker_boot = synthetic_boot_id(2);
    registration.scope = AuthorityScope::for_destination(ids.destination, ids.routing_namespace,
                                                        ids.fabric);
    registration.capabilities = 7;
    registration.provenance = ids.provenance;
    const std::vector<std::uint8_t> bytes = encode_payload(registration);
    PublisherRegistration decoded;
    ECMP_CHECK(decode_payload(bytes, limits, decoded));
    ECMP_CHECK(decoded.publisher == registration.publisher);
    ECMP_CHECK(decoded.worker_boot == registration.worker_boot);
    ECMP_CHECK(decoded.capabilities == registration.capabilities);
    ECMP_CHECK(decoded.scope.kind == ScopeKind::DESTINATION);
    ECMP_CHECK(decoded.scope.destination == ids.destination);
    std::vector<std::uint8_t> trailing = bytes;
    trailing.push_back(0);
    ECMP_CHECK(!decode_payload(trailing, limits, decoded));
  }

  {
    CreateGroupRequest request;
    request.authority = authority();
    request.group = synthetic_group_id(1);
    request.key = synthetic_group_key(ids);
    request.cost_semantics = synthetic_cost_semantics(ids, 1);
    request.hash_domain = ids.hash_domain;
    request.provenance = ids.provenance;
    request.bucket_count = *BucketCount::make(32);
    request.min_active_members = 2;
    request.members = synthetic_members(ids, 4, PathAuthorityGeneration::from_value(3));
    const std::vector<std::uint8_t> bytes = encode_payload(request);
    CreateGroupRequest decoded;
    ECMP_CHECK(decode_payload(bytes, limits, decoded));
    ECMP_CHECK(decoded.group == request.group);
    ECMP_CHECK(decoded.key == request.key);
    ECMP_CHECK(decoded.bucket_count == request.bucket_count);
    ECMP_CHECK_EQ(decoded.members.size(), std::size_t{4});
    ECMP_CHECK(decoded.members[0].member == request.members[0].member);
    ECMP_CHECK(decoded.members[0].cost == request.members[0].cost);
    std::vector<std::uint8_t> truncated(bytes.begin(), bytes.end() - 1);
    CreateGroupRequest ignored;
    ECMP_CHECK(!decode_payload(truncated, limits, ignored));
  }

  {
    RevalidateGroupRequest request;
    request.authority = authority();
    request.group = synthetic_group_id(1);
    MemberRevalidation update;
    update.member = synthetic_member_id(2000);
    update.path_authority = PathAuthorityGeneration::from_value(4);
    update.cost = synthetic_cost_claim(ids, 2000, 10, 2);
    request.members.push_back(update);
    request.multipath_generation = MultipathSetGeneration::from_value(3);
    const std::vector<std::uint8_t> bytes = encode_payload(request);
    RevalidateGroupRequest decoded;
    ECMP_CHECK(decode_payload(bytes, limits, decoded));
    ECMP_CHECK_EQ(decoded.members.size(), std::size_t{1});
    ECMP_CHECK(decoded.members[0].cost.has_value());
    ECMP_CHECK(decoded.multipath_generation.has_value());
  }

  {
    ExplainRequest request;
    request.group = synthetic_group_id(1);
    request.kind = ExplainKind::BUCKET;
    request.bucket = BucketId::from_value(17);
    const std::vector<std::uint8_t> bytes = encode_payload(request);
    ExplainRequest decoded;
    ECMP_CHECK(decode_payload(bytes, limits, decoded));
    ECMP_CHECK(decoded.kind == ExplainKind::BUCKET);
    ECMP_CHECK_EQ(decoded.bucket.value(), std::uint32_t{17});
    // An unknown selector value is rejected rather than coerced.
    std::vector<std::uint8_t> invalid = bytes;
    invalid[17] = 9;
    ExplainRequest ignored;
    ECMP_CHECK(!decode_payload(invalid, limits, ignored));
  }

  {
    // Strict enum validation on the membership source.
    CreateGroupRequest request;
    request.authority = authority();
    request.group = synthetic_group_id(1);
    request.key = synthetic_group_key(ids);
    request.cost_semantics = synthetic_cost_semantics(ids, 1);
    request.hash_domain = ids.hash_domain;
    request.provenance = ids.provenance;
    request.bucket_count = *BucketCount::make(8);
    request.members = synthetic_members(ids, 2, PathAuthorityGeneration::from_value(3));
    const std::vector<std::uint8_t> bytes = encode_payload(request);
    std::vector<std::uint8_t> invalid = bytes;
    invalid[16 + 64] = 9;  // membership source field
    CreateGroupRequest ignored;
    ECMP_CHECK(!decode_payload(invalid, limits, ignored));
  }
}

ECMP_TEST(test_mutation_result_and_snapshot_codecs) {
  GovernorLimits limits;
  MutationResult result;
  result.outcome = Outcome::STALE_PATH_AUTHORITY;
  result.conditions.add(make_condition(ConditionCode::PATH_AUTHORITY_STALE, "subject", 4, 2));
  result.detail = "detail";
  result.plan = RebalancePlanId{};
  GroupSummary summary;
  summary.id = synthetic_group_id(1);
  summary.key = synthetic_group_key(synthetic_ids(1));
  summary.lifecycle = GroupLifecycle::DEGRADED;
  summary.currentness = Currentness::from_bits(0);
  summary.membership_generation = MembershipGeneration::from_value(3);
  summary.assignment_generation = AssignmentGeneration::from_value(4);
  summary.authority_generation = AuthorityGeneration::from_value(5);
  summary.declared_members = 4;
  summary.active_members = 3;
  summary.min_active_members = 4;
  summary.bucket_count = *BucketCount::make(16);
  summary.membership_digest = domain_digest("x", {});
  summary.assignment_digest = domain_digest("y", {});
  summary.semantic_digest = domain_digest("z", {});
  result.group = summary;

  const std::vector<std::uint8_t> bytes = encode_mutation_result(result);
  MutationResult decoded;
  ECMP_CHECK(decode_mutation_result(bytes, limits, decoded));
  ECMP_CHECK(decoded.outcome == result.outcome);
  ECMP_CHECK_EQ(decoded.detail, result.detail);
  ECMP_REQUIRE(decoded.group.has_value());
  ECMP_CHECK(decoded.group->id == summary.id);
  ECMP_CHECK(decoded.group->lifecycle == GroupLifecycle::DEGRADED);
  ECMP_CHECK(decoded.group->semantic_digest == summary.semantic_digest);
  ECMP_REQUIRE(decoded.conditions.entries().size() == 1);
  ECMP_CHECK(decoded.conditions.entries()[0].code == ConditionCode::PATH_AUTHORITY_STALE);

  std::vector<std::uint8_t> trailing = bytes;
  trailing.push_back(0);
  MutationResult ignored;
  ECMP_CHECK(!decode_mutation_result(trailing, limits, ignored));

  // A mutated outcome value is preserved verbatim because outcomes are explicit
  // numeric wire values, never enum ordinals re-derived locally.
  std::vector<std::uint8_t> forged = bytes;
  forged[0] = 200;
  MutationResult forged_result;
  ECMP_CHECK(decode_mutation_result(forged, limits, forged_result));
  ECMP_CHECK_EQ(static_cast<std::uint32_t>(forged_result.outcome), std::uint32_t{200});
}
