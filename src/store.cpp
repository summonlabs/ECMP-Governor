#include <algorithm>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <system_error>
#include <vector>

#include "ecmp/bytes.hpp"
#include "ecmp/digest.hpp"
#include "ecmp/governor.hpp"
#include "ecmp/persistence.hpp"
#include "ecmp/protocol.hpp"
#include "governor_state.hpp"

namespace ecmp {
namespace {

constexpr std::string_view kStoreIntegrityDomain = "ecmp.store.v1";
constexpr std::uint8_t kStoreMagic[8] = {'E', 'C', 'M', 'P', 'G', 'O', 'V', 0x01};
constexpr std::size_t kStoreHeaderBytes = 8 + 4 + 4 + 8 + 4;
constexpr std::size_t kStoreTagBytes = 32;
constexpr std::uint32_t kPayloadVersion = 1;

std::atomic<std::uint32_t> g_temp_counter{0};

[[nodiscard]] StoreDefect fail(std::string& error, StoreDefect defect, const char* message) {
  error = message;
  return defect;
}

void encode_cost_semantics(Encoder& encoder, const CostSemantics& semantics) {
  encoder.raw(semantics.cost_class.bytes());
  encoder.raw(semantics.binding.model.bytes());
  encoder.u32(semantics.binding.model_version);
  encoder.raw(semantics.binding.route_class.bytes());
  encoder.u64(semantics.binding.policy_generation.value());
}

bool decode_cost_semantics(Decoder& decoder, CostSemantics& out) {
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
  return true;
}

// Bucket maps are persisted as explicit (bucket, owner) pairs so that a duplicate
// bucket, a missing bucket and an out-of-range bucket are all detectable, which a
// dense vector cannot express.
void encode_assignment_pairs(Encoder& encoder, const BucketAssignment& assignment) {
  encoder.u32(assignment.count.value());
  encoder.u32(static_cast<std::uint32_t>(assignment.owners.size()));
  for (std::uint32_t bucket = 0; bucket < assignment.owners.size(); ++bucket) {
    encoder.u32(bucket);
    encoder.raw(assignment.owners[bucket].bytes());
  }
}

bool decode_assignment_pairs(Decoder& decoder, const GovernorLimits& limits,
                             const std::set<ECMPMemberId>& declared,
                             BucketAssignment& out) {
  std::uint32_t count = 0;
  std::uint32_t entries = 0;
  if (!decoder.u32(count) || !decoder.u32(entries)) {
    return false;
  }
  const auto bucket_count = BucketCount::make(count);
  if (!bucket_count.has_value() || count > limits.max_buckets || entries != count) {
    return false;
  }
  out.count = *bucket_count;
  out.owners.assign(count, ECMPMemberId{});
  std::set<std::uint32_t> seen;
  for (std::uint32_t index = 0; index < entries; ++index) {
    std::uint32_t bucket = 0;
    std::array<std::uint8_t, 16> raw{};
    if (!decoder.u32(bucket) || !decoder.fixed16(raw)) {
      return false;
    }
    if (bucket >= count) {
      return false;
    }
    if (!seen.insert(bucket).second) {
      return false;
    }
    const ECMPMemberId owner = ECMPMemberId::from_bytes(raw);
    if (!owner.is_nil() && declared.find(owner) == declared.end()) {
      return false;
    }
    out.owners[bucket] = owner;
  }
  return seen.size() == count;
}

void encode_spec(Encoder& encoder, const MemberSpec& spec) { encode_member_spec(encoder, spec); }

bool decode_spec(Decoder& decoder, const GovernorLimits& limits, MemberSpec& out) {
  return decode_member_spec(decoder, limits, out);
}

void encode_member_entry(Encoder& encoder, const detail::MemberEntry& entry) {
  encode_member_record(encoder, entry.record);
  encoder.boolean(entry.path_authority_current);
  encoder.boolean(entry.path_authority_authorized);
  encoder.boolean(entry.multipath_current);
  encoder.boolean(entry.cost_current);
}

bool decode_member_entry(Decoder& decoder, const GovernorLimits& limits,
                         detail::MemberEntry& out) {
  if (!decode_member_record(decoder, limits, out.record)) {
    return false;
  }
  if (!decoder.boolean(out.path_authority_current)) {
    return false;
  }
  if (!decoder.boolean(out.path_authority_authorized)) {
    return false;
  }
  if (!decoder.boolean(out.multipath_current)) {
    return false;
  }
  return decoder.boolean(out.cost_current);
}

void encode_history(Encoder& encoder, const HistoryEntry& entry) {
  encoder.u64(entry.membership_generation.value());
  encoder.u64(entry.assignment_generation.value());
  encoder.u64(entry.authority_generation.value());
  encoder.u8(static_cast<std::uint8_t>(entry.reason));
  encoder.raw(entry.publisher.bytes());
  encoder.u64(entry.epoch.value());
  encoder.u64(entry.churn);
  encoder.u64(entry.moves_recorded);
  encoder.boolean(entry.plan.has_value());
  if (entry.plan.has_value()) {
    encoder.raw(entry.plan->bytes());
  }
  encoder.raw(entry.membership_digest.bytes());
  encoder.raw(entry.assignment_digest.bytes());
}

bool decode_history(Decoder& decoder, HistoryEntry& out) {
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
  std::uint8_t reason = 0;
  if (!decoder.u8(reason) || reason < 1 || reason > 16) {
    return false;
  }
  out.reason = static_cast<ChangeReason>(reason);
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return false;
  }
  out.publisher = PublisherId::from_bytes(raw);
  if (!decoder.u64(value)) {
    return false;
  }
  out.epoch = CoordinatorEpoch::from_value(value);
  if (!decoder.u64(out.churn) || !decoder.u64(out.moves_recorded)) {
    return false;
  }
  bool has_plan = false;
  if (!decoder.boolean(has_plan)) {
    return false;
  }
  if (has_plan) {
    if (!decoder.fixed16(raw)) {
      return false;
    }
    out.plan = RebalancePlanId::from_bytes(raw);
  }
  std::array<std::uint8_t, 32> digest{};
  if (!decoder.raw(digest)) {
    return false;
  }
  out.membership_digest = Digest::from_bytes(digest);
  if (!decoder.raw(digest)) {
    return false;
  }
  out.assignment_digest = Digest::from_bytes(digest);
  return true;
}

void encode_group(Encoder& encoder, const detail::GroupState& group) {
  encoder.raw(group.id.bytes());
  encode_group_key(encoder, group.key);
  encoder.u8(static_cast<std::uint8_t>(group.source));
  encoder.u8(static_cast<std::uint8_t>(group.lifecycle));
  encoder.u32(group.currentness.bits());
  encoder.u64(group.membership_generation.value());
  encoder.u64(group.assignment_generation.value());
  encoder.u64(group.authority_generation.value());
  encode_cost_semantics(encoder, group.cost_semantics);
  encoder.i64(group.canonical_cost.units);
  encoder.u32(group.canonical_cost.scale);
  encoder.raw(group.hash_domain.bytes());
  encoder.u32(group.bucket_count.value());
  encoder.u32(group.min_active_members);
  encoder.raw(group.multipath_set.bytes());
  encoder.u64(group.multipath_generation.value());
  encoder.raw(group.authority_publisher.bytes());
  encoder.raw(group.authority_boot.bytes());
  encoder.u64(group.bound_epoch.value());
  encoder.raw(group.provenance.bytes());
  encoder.raw(group.successor.bytes());
  encoder.raw(group.predecessor.bytes());
  encoder.raw(group.declared_digest.bytes());
  encoder.u32(static_cast<std::uint32_t>(group.members.size()));
  for (const detail::MemberEntry& member : group.members) {
    encode_member_entry(encoder, member);
  }
  encode_assignment_pairs(encoder, group.assignment);
  encoder.boolean(group.plan.has_value());
  if (group.plan.has_value()) {
    const detail::PlanEntry& plan = *group.plan;
    encoder.raw(plan.plan.bytes());
    encoder.u64(plan.from_membership.value());
    encoder.u64(plan.from_assignment.value());
    encoder.u64(plan.from_authority.value());
    encoder.u64(plan.target_membership.value());
    encoder.raw(plan.target_membership_digest.bytes());
    encoder.u32(static_cast<std::uint32_t>(plan.target_members.size()));
    for (const MemberSpec& spec : plan.target_members) {
      encode_spec(encoder, spec);
    }
    encoder.u32(static_cast<std::uint32_t>(plan.moves.size()));
    for (const BucketMove& move : plan.moves) {
      encode_bucket_move(encoder, move);
    }
    encode_assignment_pairs(encoder, plan.assignment);
    encoder.raw(plan.assignment_digest.bytes());
    encoder.u64(plan.epoch.value());
    encoder.raw(plan.publisher.bytes());
  }
  encoder.u32(static_cast<std::uint32_t>(group.history.size()));
  for (const HistoryEntry& entry : group.history) {
    encode_history(encoder, entry);
  }
  encoder.boolean(group.last_rebalance.has_value());
  if (group.last_rebalance.has_value()) {
    encode_rebalance_record(encoder, *group.last_rebalance);
  }
}

struct GroupDecodeResult {
  StoreDefect defect = StoreDefect::NONE;
  std::string detail;
};

GroupDecodeResult decode_group(Decoder& decoder, const GovernorLimits& limits,
                               detail::GroupState& out) {
  GroupDecodeResult result;
  std::array<std::uint8_t, 16> raw{};
  if (!decoder.fixed16(raw)) {
    return {StoreDefect::TRUNCATED, "group id"};
  }
  out.id = ECMPGroupId::from_bytes(raw);
  if (out.id.is_nil()) {
    return {StoreDefect::STRUCTURE, "nil group id"};
  }
  if (!decode_group_key(decoder, out.key) || !out.key.is_well_formed()) {
    return {StoreDefect::STRUCTURE, "group key"};
  }
  std::uint8_t source = 0;
  std::uint8_t lifecycle = 0;
  if (!decoder.u8(source) || source < 1 || source > 2) {
    return {StoreDefect::STRUCTURE, "membership source"};
  }
  if (!decoder.u8(lifecycle) || lifecycle < 1 || lifecycle > kGroupLifecycleCount) {
    return {StoreDefect::STRUCTURE, "lifecycle"};
  }
  out.source = static_cast<MembershipSource>(source);
  out.lifecycle = static_cast<GroupLifecycle>(lifecycle);
  std::uint32_t bits = 0;
  if (!decoder.u32(bits) || bits >= (1u << kCurrentnessCauseCount)) {
    return {StoreDefect::STRUCTURE, "currentness"};
  }
  out.currentness = Currentness::from_bits(bits);
  std::uint64_t value = 0;
  if (!decoder.u64(value)) {
    return {StoreDefect::TRUNCATED, "generations"};
  }
  out.membership_generation = MembershipGeneration::from_value(value);
  if (!decoder.u64(value)) {
    return {StoreDefect::TRUNCATED, "generations"};
  }
  out.assignment_generation = AssignmentGeneration::from_value(value);
  if (!decoder.u64(value)) {
    return {StoreDefect::TRUNCATED, "generations"};
  }
  out.authority_generation = AuthorityGeneration::from_value(value);
  if (!decode_cost_semantics(decoder, out.cost_semantics) ||
      !out.cost_semantics.is_well_formed()) {
    return {StoreDefect::STRUCTURE, "cost semantics"};
  }
  if (!decoder.i64(out.canonical_cost.units) || !decoder.u32(out.canonical_cost.scale) ||
      !out.canonical_cost.is_well_formed()) {
    return {StoreDefect::STRUCTURE, "canonical cost"};
  }
  if (!decoder.fixed16(raw)) {
    return {StoreDefect::TRUNCATED, "hash domain"};
  }
  out.hash_domain = HashDomainId::from_bytes(raw);
  if (out.hash_domain.is_nil()) {
    return {StoreDefect::STRUCTURE, "hash domain"};
  }
  std::uint32_t buckets = 0;
  if (!decoder.u32(buckets)) {
    return {StoreDefect::TRUNCATED, "bucket count"};
  }
  const auto bucket_count = BucketCount::make(buckets);
  if (!bucket_count.has_value() || buckets > limits.max_buckets) {
    return {StoreDefect::STRUCTURE, "bucket count"};
  }
  out.bucket_count = *bucket_count;
  if (!decoder.u32(out.min_active_members) || out.min_active_members == 0 ||
      out.min_active_members > limits.max_members_per_group) {
    return {StoreDefect::STRUCTURE, "min active members"};
  }
  if (!decoder.fixed16(raw)) {
    return {StoreDefect::TRUNCATED, "multipath set"};
  }
  out.multipath_set = MultipathSetId::from_bytes(raw);
  if (!decoder.u64(value)) {
    return {StoreDefect::TRUNCATED, "multipath generation"};
  }
  out.multipath_generation = MultipathSetGeneration::from_value(value);
  if (!decoder.fixed16(raw)) {
    return {StoreDefect::TRUNCATED, "authority publisher"};
  }
  out.authority_publisher = PublisherId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return {StoreDefect::TRUNCATED, "authority boot"};
  }
  out.authority_boot = WorkerBootId::from_bytes(raw);
  if (!decoder.u64(value)) {
    return {StoreDefect::TRUNCATED, "bound epoch"};
  }
  out.bound_epoch = CoordinatorEpoch::from_value(value);
  if (!decoder.fixed16(raw)) {
    return {StoreDefect::TRUNCATED, "provenance"};
  }
  out.provenance = ProvenanceId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return {StoreDefect::TRUNCATED, "successor"};
  }
  out.successor = ECMPGroupId::from_bytes(raw);
  if (!decoder.fixed16(raw)) {
    return {StoreDefect::TRUNCATED, "predecessor"};
  }
  out.predecessor = ECMPGroupId::from_bytes(raw);
  std::array<std::uint8_t, 32> digest{};
  if (!decoder.raw(digest)) {
    return {StoreDefect::TRUNCATED, "declared digest"};
  }
  out.declared_digest = Digest::from_bytes(digest);

  std::uint32_t member_count = 0;
  if (!decoder.u32(member_count)) {
    return {StoreDefect::TRUNCATED, "member count"};
  }
  if (member_count > limits.max_members_per_group) {
    return {StoreDefect::STRUCTURE, "member count"};
  }
  out.members.clear();
  out.members.reserve(member_count);
  std::set<ECMPMemberId> member_ids;
  std::uint32_t declared = 0;
  for (std::uint32_t index = 0; index < member_count; ++index) {
    detail::MemberEntry entry;
    if (!decode_member_entry(decoder, limits, entry)) {
      return {StoreDefect::TRUNCATED, "member record"};
    }
    if (entry.record.member.is_nil() || entry.record.path.is_nil() ||
        !entry.record.cost.is_well_formed()) {
      return {StoreDefect::STRUCTURE, "member record"};
    }
    if (!member_ids.insert(entry.record.member).second) {
      return {StoreDefect::STRUCTURE, "duplicate member"};
    }
    if (entry.record.declared) {
      ++declared;
    }
    out.members.push_back(std::move(entry));
  }
  if (declared > limits.max_members_per_group || declared > out.bucket_count.value()) {
    return {StoreDefect::STRUCTURE, "declared member count"};
  }

  const auto assignment = decode_assignment_pairs(decoder, limits, member_ids, out.assignment);
  if (!assignment) {
    return {StoreDefect::STRUCTURE, "bucket assignment"};
  }

  bool has_plan = false;
  if (!decoder.boolean(has_plan)) {
    return {StoreDefect::TRUNCATED, "plan"};
  }
  if (has_plan) {
    detail::PlanEntry plan;
    if (!decoder.fixed16(raw)) {
      return {StoreDefect::TRUNCATED, "plan id"};
    }
    plan.plan = RebalancePlanId::from_bytes(raw);
    if (!decoder.u64(value)) {
      return {StoreDefect::TRUNCATED, "plan generations"};
    }
    plan.from_membership = MembershipGeneration::from_value(value);
    if (!decoder.u64(value)) {
      return {StoreDefect::TRUNCATED, "plan generations"};
    }
    plan.from_assignment = AssignmentGeneration::from_value(value);
    if (!decoder.u64(value)) {
      return {StoreDefect::TRUNCATED, "plan generations"};
    }
    plan.from_authority = AuthorityGeneration::from_value(value);
    if (!decoder.u64(value)) {
      return {StoreDefect::TRUNCATED, "plan generations"};
    }
    plan.target_membership = MembershipGeneration::from_value(value);
    if (!decoder.raw(digest)) {
      return {StoreDefect::TRUNCATED, "plan digest"};
    }
    plan.target_membership_digest = Digest::from_bytes(digest);
    std::uint32_t target_count = 0;
    if (!decoder.u32(target_count) || target_count > limits.max_members_per_group) {
      return {StoreDefect::STRUCTURE, "plan target members"};
    }
    for (std::uint32_t index = 0; index < target_count; ++index) {
      MemberSpec spec;
      if (!decode_spec(decoder, limits, spec)) {
        return {StoreDefect::TRUNCATED, "plan target member"};
      }
      plan.target_members.push_back(std::move(spec));
    }
    std::uint32_t move_count = 0;
    if (!decoder.u32(move_count) || move_count > limits.max_buckets) {
      return {StoreDefect::STRUCTURE, "plan moves"};
    }
    for (std::uint32_t index = 0; index < move_count; ++index) {
      BucketMove move;
      if (!decode_bucket_move(decoder, move)) {
        return {StoreDefect::TRUNCATED, "plan move"};
      }
      plan.moves.push_back(move);
    }
    if (!decode_assignment_pairs(decoder, limits, member_ids, plan.assignment)) {
      return {StoreDefect::STRUCTURE, "plan assignment"};
    }
    if (!decoder.raw(digest)) {
      return {StoreDefect::TRUNCATED, "plan assignment digest"};
    }
    plan.assignment_digest = Digest::from_bytes(digest);
    if (!decoder.u64(value)) {
      return {StoreDefect::TRUNCATED, "plan epoch"};
    }
    plan.epoch = CoordinatorEpoch::from_value(value);
    if (!decoder.fixed16(raw)) {
      return {StoreDefect::TRUNCATED, "plan publisher"};
    }
    plan.publisher = PublisherId::from_bytes(raw);
    out.plan = std::move(plan);
  }

  std::uint32_t history_count = 0;
  if (!decoder.u32(history_count) || history_count > limits.max_history) {
    return {StoreDefect::STRUCTURE, "history"};
  }
  for (std::uint32_t index = 0; index < history_count; ++index) {
    HistoryEntry entry;
    if (!decode_history(decoder, entry)) {
      return {StoreDefect::TRUNCATED, "history entry"};
    }
    out.history.push_back(std::move(entry));
  }

  bool has_rebalance = false;
  if (!decoder.boolean(has_rebalance)) {
    return {StoreDefect::TRUNCATED, "rebalance record"};
  }
  if (has_rebalance) {
    RebalanceRecord record;
    if (!decode_rebalance_record(decoder, limits, record)) {
      return {StoreDefect::TRUNCATED, "rebalance record"};
    }
    out.last_rebalance = std::move(record);
  }
  return result;
}

// Recovery is deliberately conservative: no live authority survives a restart, so
// every member's upstream facts are marked unproven and the group requires
// explicit revalidation.  The durable bucket map is retained as the desired
// assignment, but it is not authoritative until revalidation re-establishes it.
void recover_group(ecmp::detail::GovernorState& state, ecmp::detail::GroupState& group,
                   std::uint64_t stored_epoch) {
  for (ecmp::detail::MemberEntry& member : group.members) {
    member.path_authority_current = false;
    member.path_authority_authorized = false;
    member.multipath_current = false;
    member.cost_current = false;
  }
  group.currentness.add(CurrentnessCause::STALE_EPOCH);
  group.currentness.add(CurrentnessCause::REVALIDATION_REQUIRED);
  group.plan.reset();
  const auto next = group.authority_generation.next();
  if (next.has_value()) {
    group.authority_generation = *next;
  }
  group.declared_digest = ecmp::detail::compute_declared_digest(group);
  ecmp::detail::RefreshContext context;
  context.reason = ChangeReason::RECOVERY;
  context.event = GroupEvent::INVALIDATE_EPOCH;
  context.publisher = group.authority_publisher;
  context.worker_boot = group.authority_boot;
  context.epoch = CoordinatorEpoch::from_value(stored_epoch);
  context.bind_authority = false;
  context.recompute_assignment = false;
  ConditionList ignored(state.limits.max_explanation_entries);
  (void)ecmp::detail::refresh_group(state, group, context, ignored);
}

}  // namespace

std::string_view to_string(StoreDefect defect) noexcept {
  switch (defect) {
    case StoreDefect::NONE: return "NONE";
    case StoreDefect::IO_ERROR: return "IO_ERROR";
    case StoreDefect::EMPTY: return "EMPTY";
    case StoreDefect::BAD_MAGIC: return "BAD_MAGIC";
    case StoreDefect::BAD_VERSION: return "BAD_VERSION";
    case StoreDefect::RESERVED_NOT_ZERO: return "RESERVED_NOT_ZERO";
    case StoreDefect::TRUNCATED: return "TRUNCATED";
    case StoreDefect::TRAILING_BYTES: return "TRAILING_BYTES";
    case StoreDefect::INTEGRITY_FAILURE: return "INTEGRITY_FAILURE";
    case StoreDefect::PAYLOAD_TOO_LARGE: return "PAYLOAD_TOO_LARGE";
    case StoreDefect::STRUCTURE: return "STRUCTURE";
  }
  return "UNKNOWN_STORE_DEFECT";
}

ConditionCode condition_for(StoreDefect defect) noexcept {
  switch (defect) {
    case StoreDefect::NONE: return ConditionCode::NONE;
    case StoreDefect::IO_ERROR: return ConditionCode::STORE_IO;
    case StoreDefect::EMPTY: return ConditionCode::STORE_STRUCTURE;
    case StoreDefect::BAD_MAGIC: return ConditionCode::STORE_MAGIC;
    case StoreDefect::BAD_VERSION: return ConditionCode::STORE_VERSION;
    case StoreDefect::RESERVED_NOT_ZERO: return ConditionCode::STORE_STRUCTURE;
    case StoreDefect::TRUNCATED: return ConditionCode::STORE_STRUCTURE;
    case StoreDefect::TRAILING_BYTES: return ConditionCode::STORE_TRAILING_BYTES;
    case StoreDefect::INTEGRITY_FAILURE: return ConditionCode::STORE_INTEGRITY;
    case StoreDefect::PAYLOAD_TOO_LARGE: return ConditionCode::STORE_RECORD_LIMIT;
    case StoreDefect::STRUCTURE: return ConditionCode::STORE_STRUCTURE;
  }
  return ConditionCode::STORE_STRUCTURE;
}

std::vector<std::uint8_t> encode_store_file(std::uint64_t coordinator_epoch,
                                            std::span<const std::uint8_t> payload) {
  Encoder encoder;
  encoder.raw(std::span<const std::uint8_t>(kStoreMagic, sizeof(kStoreMagic)));
  encoder.u32(kPersistenceFormatVersion);
  encoder.u32(0);
  encoder.u64(coordinator_epoch);
  encoder.u32(static_cast<std::uint32_t>(payload.size()));
  encoder.raw(payload);
  const Digest tag = domain_digest(kStoreIntegrityDomain, encoder.bytes());
  encoder.raw(tag.bytes());
  return encoder.take();
}

StoreDefect decode_store_file(std::span<const std::uint8_t> bytes, const GovernorLimits& limits,
                              StoreFileInfo& info, std::vector<std::uint8_t>& payload) {
  if (bytes.empty()) {
    return StoreDefect::EMPTY;
  }
  if (bytes.size() < kStoreHeaderBytes + kStoreTagBytes) {
    return StoreDefect::TRUNCATED;
  }
  Decoder decoder(bytes, limits.max_persistence_record_bytes);
  for (const std::uint8_t expected : kStoreMagic) {
    std::uint8_t actual = 0;
    if (!decoder.u8(actual)) {
      return StoreDefect::TRUNCATED;
    }
    if (actual != expected) {
      return StoreDefect::BAD_MAGIC;
    }
  }
  std::uint32_t version = 0;
  std::uint32_t reserved = 0;
  std::uint64_t epoch = 0;
  std::uint32_t payload_bytes = 0;
  if (!decoder.u32(version) || !decoder.u32(reserved) || !decoder.u64(epoch) ||
      !decoder.u32(payload_bytes)) {
    return StoreDefect::TRUNCATED;
  }
  if (version != kPersistenceFormatVersion) {
    return StoreDefect::BAD_VERSION;
  }
  if (reserved != 0) {
    return StoreDefect::RESERVED_NOT_ZERO;
  }
  if (payload_bytes > limits.max_persistence_record_bytes) {
    return StoreDefect::PAYLOAD_TOO_LARGE;
  }
  const std::size_t expected_size = kStoreHeaderBytes + payload_bytes + kStoreTagBytes;
  if (bytes.size() < expected_size) {
    return StoreDefect::TRUNCATED;
  }
  if (bytes.size() > expected_size) {
    return StoreDefect::TRAILING_BYTES;
  }
  const auto signed_region = bytes.first(kStoreHeaderBytes + payload_bytes);
  const Digest expected_tag = domain_digest(kStoreIntegrityDomain, signed_region);
  if (!std::equal(expected_tag.bytes().begin(), expected_tag.bytes().end(),
                  bytes.begin() + static_cast<std::ptrdiff_t>(expected_size - kStoreTagBytes))) {
    return StoreDefect::INTEGRITY_FAILURE;
  }
  info.coordinator_epoch = epoch;
  info.payload_bytes = payload_bytes;
  payload.assign(bytes.begin() + static_cast<std::ptrdiff_t>(kStoreHeaderBytes),
                 bytes.begin() + static_cast<std::ptrdiff_t>(kStoreHeaderBytes + payload_bytes));
  return StoreDefect::NONE;
}

StoreDefect write_store_file_atomic(const std::filesystem::path& path,
                                    std::span<const std::uint8_t> image, std::string& error) {
  std::error_code ec;
  const std::filesystem::path directory = path.parent_path();
  if (!directory.empty() && !std::filesystem::exists(directory, ec)) {
    std::filesystem::create_directories(directory, ec);
    if (ec) {
      return fail(error, StoreDefect::IO_ERROR, "cannot create store directory");
    }
  }
  const std::filesystem::path temp =
      path.string() + ".tmp." + std::to_string(g_temp_counter.fetch_add(1));
  {
    std::ofstream out(temp, std::ios::binary | std::ios::trunc);
    if (!out) {
      return fail(error, StoreDefect::IO_ERROR, "cannot open temporary store file");
    }
    out.write(reinterpret_cast<const char*>(image.data()),
              static_cast<std::streamsize>(image.size()));
    out.flush();
    if (!out) {
      out.close();
      std::filesystem::remove(temp, ec);
      return fail(error, StoreDefect::IO_ERROR, "cannot write temporary store file");
    }
  }
  std::filesystem::rename(temp, path, ec);
  if (ec) {
    std::filesystem::remove(temp, ec);
    return fail(error, StoreDefect::IO_ERROR, "cannot replace store file atomically");
  }
  return StoreDefect::NONE;
}

StoreDefect read_store_file(const std::filesystem::path& path, std::vector<std::uint8_t>& bytes,
                            std::string& error) {
  std::error_code ec;
  if (!std::filesystem::exists(path, ec)) {
    return fail(error, StoreDefect::IO_ERROR, "store file does not exist");
  }
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return fail(error, StoreDefect::IO_ERROR, "cannot open store file");
  }
  in.seekg(0, std::ios::end);
  const std::streamoff size = in.tellg();
  if (size < 0) {
    return fail(error, StoreDefect::IO_ERROR, "cannot size store file");
  }
  in.seekg(0, std::ios::beg);
  bytes.assign(static_cast<std::size_t>(size), 0);
  if (size > 0) {
    in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(size));
    if (!in) {
      return fail(error, StoreDefect::IO_ERROR, "cannot read store file");
    }
  }
  return StoreDefect::NONE;
}

namespace detail {

std::vector<std::uint8_t> encode_governor_payload(const GovernorState& state) {
  Encoder encoder(state.limits.max_persistence_record_bytes);
  encoder.u32(kPayloadVersion);
  encoder.u32(static_cast<std::uint32_t>(state.groups.size()));
  for (const auto& entry : state.groups) {
    encode_group(encoder, entry.second);
  }
  encoder.u64(state.committed_rebalances);
  encoder.u32(static_cast<std::uint32_t>(state.attempts.size()));
  for (const MutationAttemptId& attempt : state.attempt_order) {
    const auto it = state.attempts.find(attempt);
    if (it == state.attempts.end()) {
      continue;
    }
    encoder.raw(attempt.bytes());
    encoder.raw(it->second.payload.bytes());
    encoder.u32(static_cast<std::uint32_t>(it->second.outcome));
    encoder.raw(it->second.group.bytes());
    encoder.u32(static_cast<std::uint32_t>(it->second.primary));
    encoder.text(it->second.detail);
  }
  encoder.u32(0);  // reserved payload trailer
  return encoder.take();
}

StoreDefect decode_governor_payload(std::span<const std::uint8_t> bytes,
                                    const GovernorLimits& limits,
                                    std::map<ECMPGroupId, GroupState>& groups,
                                    std::uint64_t& committed_rebalances, std::string& detail) {
  Decoder decoder(bytes, limits.max_persistence_record_bytes);
  std::uint32_t version = 0;
  std::uint32_t group_count = 0;
  if (!decoder.u32(version) || !decoder.u32(group_count)) {
    detail = "payload header";
    return StoreDefect::TRUNCATED;
  }
  if (version != kPayloadVersion) {
    detail = "payload version";
    return StoreDefect::BAD_VERSION;
  }
  if (group_count > limits.max_groups) {
    detail = "group count";
    return StoreDefect::STRUCTURE;
  }
  groups.clear();
  for (std::uint32_t index = 0; index < group_count; ++index) {
    GroupState group;
    const GroupDecodeResult result = decode_group(decoder, limits, group);
    if (result.defect != StoreDefect::NONE) {
      detail = result.detail;
      return result.defect;
    }
    if (!groups.emplace(group.id, std::move(group)).second) {
      detail = "duplicate group";
      return StoreDefect::STRUCTURE;
    }
  }
  if (!decoder.u64(committed_rebalances)) {
    detail = "committed rebalances";
    return StoreDefect::TRUNCATED;
  }
  std::uint32_t attempt_count = 0;
  if (!decoder.u32(attempt_count) || attempt_count > limits.max_attempts_remembered) {
    detail = "attempt count";
    return StoreDefect::STRUCTURE;
  }
  // Attempt records are validated but not re-installed: live idempotency memory
  // is not live authority, and the bounded window restarts empty.
  for (std::uint32_t index = 0; index < attempt_count; ++index) {
    std::array<std::uint8_t, 16> raw{};
    std::array<std::uint8_t, 32> digest{};
    std::uint32_t outcome = 0;
    std::uint32_t primary = 0;
    std::string text;
    if (!decoder.fixed16(raw) || !decoder.raw(digest) || !decoder.u32(outcome) ||
        !decoder.fixed16(raw) || !decoder.u32(primary) || !decoder.text(text, 256)) {
      detail = "attempt record";
      return StoreDefect::TRUNCATED;
    }
  }
  std::uint32_t reserved = 0;
  if (!decoder.u32(reserved)) {
    detail = "payload trailer";
    return StoreDefect::TRUNCATED;
  }
  if (reserved != 0) {
    detail = "payload trailer";
    return StoreDefect::STRUCTURE;
  }
  if (!decoder.at_end()) {
    detail = "payload trailing bytes";
    return StoreDefect::TRAILING_BYTES;
  }
  return StoreDefect::NONE;
}

}  // namespace detail

SaveReport EcmpGovernor::save(const std::filesystem::path& path) const {
  std::shared_lock lock(state_->mutex);
  SaveReport report;
  const std::vector<std::uint8_t> payload = detail::encode_governor_payload(*state_);
  if (payload.size() > state_->limits.max_persistence_record_bytes) {
    report.ok = false;
    report.outcome = Outcome::RESOURCE_LIMIT;
    report.detail = "store record limit exceeded";
    return report;
  }
  const std::vector<std::uint8_t> image =
      encode_store_file(state_->epoch.value(), payload);
  std::string error;
  const StoreDefect defect = write_store_file_atomic(path, image, error);
  report.ok = defect == StoreDefect::NONE;
  report.outcome = report.ok ? Outcome::NO_CHANGE : Outcome::STORE_ERROR;
  report.detail = report.ok ? std::string() : error;
  report.bytes = report.ok ? image.size() : 0;
  return report;
}

LoadReport EcmpGovernor::load(const std::filesystem::path& path) {
  std::unique_lock lock(state_->mutex);
  LoadReport report;
  std::vector<std::uint8_t> bytes;
  std::string error;
  StoreDefect defect = read_store_file(path, bytes, error);
  if (defect != StoreDefect::NONE) {
    report.detail = error;
    report.outcome = Outcome::STORE_ERROR;
    return report;
  }
  StoreFileInfo info;
  std::vector<std::uint8_t> payload;
  defect = decode_store_file(bytes, state_->limits, info, payload);
  if (defect != StoreDefect::NONE) {
    report.detail = std::string(to_string(defect));
    report.outcome = Outcome::STORE_ERROR;
    return report;
  }
  if (!state_->groups.empty()) {
    report.detail = "load requires an empty governor";
    report.outcome = Outcome::MALFORMED_REQUEST;
    return report;
  }
  std::map<ECMPGroupId, detail::GroupState> groups;
  std::uint64_t committed = 0;
  std::string detail_text;
  defect = detail::decode_governor_payload(payload, state_->limits, groups, committed, detail_text);
  if (defect != StoreDefect::NONE) {
    report.detail = std::string(to_string(defect)) + ":" + detail_text;
    report.outcome = Outcome::STORE_ERROR;
    return report;
  }

  const CoordinatorEpoch stored = CoordinatorEpoch::from_value(info.coordinator_epoch);
  if (stored < state_->epoch) {
    report.detail = "store epoch is older than the running epoch";
    report.outcome = Outcome::STALE_EPOCH;
    return report;
  }
  state_->groups = std::move(groups);
  state_->committed_rebalances = committed;
  state_->epoch = stored;
  state_->publishers.clear();
  state_->fenced_boots.clear();
  state_->attempts.clear();
  state_->attempt_order.clear();
  state_->path_index.clear();
  state_->multipath_index.clear();
  state_->cost_class_index.clear();
  state_->authority_index.clear();
  state_->key_index.clear();
  state_->total_members = 0;

  for (auto& entry : state_->groups) {
    detail::GroupState& group = entry.second;
    recover_group(*state_, group, info.coordinator_epoch);
    state_->total_members += group.declared_count();
    state_->index_group_paths(group);
    state_->index_cost_class(group);
    state_->key_index.emplace(group.key, group.id);
  }
  report.ok = true;
  report.outcome = Outcome::CREATED;
  report.groups_loaded = static_cast<std::uint32_t>(state_->groups.size());
  report.stored_epoch = stored;
  report.detail = "recovered conservatively";
  return report;
}

}  // namespace ecmp
