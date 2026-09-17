#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "ecmp/limits.hpp"

namespace ecmp {

namespace detail {

[[nodiscard]] constexpr std::uint8_t hex_nibble(char c) noexcept {
  if (c >= '0' && c <= '9') {
    return static_cast<std::uint8_t>(c - '0');
  }
  if (c >= 'a' && c <= 'f') {
    return static_cast<std::uint8_t>(c - 'a' + 10);
  }
  if (c >= 'A' && c <= 'F') {
    return static_cast<std::uint8_t>(c - 'A' + 10);
  }
  return 0xFFu;
}

}  // namespace detail

// 128-bit strongly typed identity.  Canonical text encoding is exactly 32
// lowercase hexadecimal digits; parsing accepts either case and rejects every
// other spelling, so a malformed encoding can never be silently truncated or
// reinterpreted.  Distinct tags make cross-domain conversion a compile error.
template <class Tag>
class StrongId {
 public:
  static constexpr std::size_t kByteCount = 16;
  static constexpr std::size_t kTextLength = 32;

  constexpr StrongId() noexcept = default;

  [[nodiscard]] static constexpr StrongId from_bytes(
      const std::array<std::uint8_t, kByteCount>& raw) noexcept {
    StrongId id;
    id.bytes_ = raw;
    return id;
  }

  // Test and tooling helper: builds an identity from two big-endian words.
  [[nodiscard]] static StrongId from_u64(std::uint64_t high, std::uint64_t low) noexcept {
    std::array<std::uint8_t, kByteCount> raw{};
    for (std::size_t i = 0; i < 8; ++i) {
      raw[i] = static_cast<std::uint8_t>((high >> (8u * (7u - i))) & 0xFFu);
      raw[8 + i] = static_cast<std::uint8_t>((low >> (8u * (7u - i))) & 0xFFu);
    }
    return from_bytes(raw);
  }

  [[nodiscard]] static std::optional<StrongId> parse(std::string_view text) noexcept {
    if (text.size() != kTextLength) {
      return std::nullopt;
    }
    std::array<std::uint8_t, kByteCount> raw{};
    for (std::size_t i = 0; i < kByteCount; ++i) {
      const std::uint8_t hi = detail::hex_nibble(text[2 * i]);
      const std::uint8_t lo = detail::hex_nibble(text[(2 * i) + 1]);
      if (hi == 0xFFu || lo == 0xFFu) {
        return std::nullopt;
      }
      raw[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return from_bytes(raw);
  }

  [[nodiscard]] constexpr bool is_nil() const noexcept {
    for (const std::uint8_t byte : bytes_) {
      if (byte != 0) {
        return false;
      }
    }
    return true;
  }

  [[nodiscard]] constexpr const std::array<std::uint8_t, kByteCount>& bytes() const noexcept {
    return bytes_;
  }

  [[nodiscard]] std::string to_text() const {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out(kTextLength, '0');
    for (std::size_t i = 0; i < kByteCount; ++i) {
      out[2 * i] = kHex[bytes_[i] >> 4];
      out[(2 * i) + 1] = kHex[bytes_[i] & 0x0Fu];
    }
    return out;
  }

  friend constexpr auto operator<=>(const StrongId&, const StrongId&) noexcept = default;
  friend constexpr bool operator==(const StrongId&, const StrongId&) noexcept = default;

 private:
  std::array<std::uint8_t, kByteCount> bytes_{};
};

// Monotonic 64-bit generation counter of a specific domain.  Increment is
// checked: crossing the maximum yields no successor instead of wrapping, which
// is surfaced as a structured GENERATION_EXHAUSTED outcome.
template <class Tag>
class Generation {
 public:
  static constexpr std::uint64_t kMaximum = 0xFFFFFFFFFFFFFFFFull;

  constexpr Generation() noexcept = default;

  [[nodiscard]] static constexpr Generation from_value(std::uint64_t value) noexcept {
    Generation generation;
    generation.value_ = value;
    return generation;
  }

  [[nodiscard]] constexpr std::uint64_t value() const noexcept { return value_; }
  [[nodiscard]] constexpr bool is_zero() const noexcept { return value_ == 0; }

  [[nodiscard]] constexpr std::optional<Generation> next() const noexcept {
    if (value_ == kMaximum) {
      return std::nullopt;
    }
    return from_value(value_ + 1);
  }

  friend constexpr auto operator<=>(const Generation&, const Generation&) noexcept = default;
  friend constexpr bool operator==(const Generation&, const Generation&) noexcept = default;

 private:
  std::uint64_t value_ = 0;
};

// Bucket index inside the governed selection space.
class BucketId {
 public:
  constexpr BucketId() noexcept = default;

  [[nodiscard]] static constexpr BucketId from_value(std::uint32_t value) noexcept {
    BucketId id;
    id.value_ = value;
    return id;
  }

  [[nodiscard]] constexpr std::uint32_t value() const noexcept { return value_; }

  friend constexpr auto operator<=>(const BucketId&, const BucketId&) noexcept = default;
  friend constexpr bool operator==(const BucketId&, const BucketId&) noexcept = default;

 private:
  std::uint32_t value_ = 0;
};

// Size of the governed selection space.  Always bounded and always non-zero.
class BucketCount {
 public:
  constexpr BucketCount() noexcept = default;

  [[nodiscard]] static constexpr std::optional<BucketCount> make(std::uint32_t value) noexcept {
    if (value == 0 || value > kAbsoluteMaxBuckets) {
      return std::nullopt;
    }
    BucketCount count;
    count.value_ = value;
    return count;
  }

  [[nodiscard]] constexpr std::uint32_t value() const noexcept { return value_; }
  [[nodiscard]] constexpr bool is_valid() const noexcept { return value_ != 0; }

  friend constexpr auto operator<=>(const BucketCount&, const BucketCount&) noexcept = default;
  friend constexpr bool operator==(const BucketCount&, const BucketCount&) noexcept = default;

 private:
  std::uint32_t value_ = 0;
};

// --- Identity domains -------------------------------------------------------
// Each of these is a distinct type: passing an ECMPMemberId where an
// ECMPGroupId is expected does not compile.

#define ECMP_DECLARE_ID(name)          \
  struct name##Tag;                    \
  using name = StrongId<name##Tag>

ECMP_DECLARE_ID(ECMPGroupId);
ECMP_DECLARE_ID(ECMPMemberId);
ECMP_DECLARE_ID(PathId);
ECMP_DECLARE_ID(MultipathSetId);
ECMP_DECLARE_ID(RouteId);
ECMP_DECLARE_ID(PublisherId);
ECMP_DECLARE_ID(WorkerBootId);
ECMP_DECLARE_ID(MutationAttemptId);
ECMP_DECLARE_ID(RebalancePlanId);
ECMP_DECLARE_ID(HashDomainId);
ECMP_DECLARE_ID(CostClassId);
ECMP_DECLARE_ID(CostModelId);
ECMP_DECLARE_ID(RouteClassId);
ECMP_DECLARE_ID(FabricId);
ECMP_DECLARE_ID(RoutingNamespaceId);
ECMP_DECLARE_ID(DestinationId);
ECMP_DECLARE_ID(ProvenanceId);

#undef ECMP_DECLARE_ID

// --- Generation domains -----------------------------------------------------

#define ECMP_DECLARE_GENERATION(name)  \
  struct name##Tag;                    \
  using name = Generation<name##Tag>

ECMP_DECLARE_GENERATION(MembershipGeneration);
ECMP_DECLARE_GENERATION(AssignmentGeneration);
ECMP_DECLARE_GENERATION(AuthorityGeneration);
ECMP_DECLARE_GENERATION(MemberGeneration);
ECMP_DECLARE_GENERATION(PathAuthorityGeneration);
ECMP_DECLARE_GENERATION(MultipathSetGeneration);
ECMP_DECLARE_GENERATION(CostPolicyGeneration);
ECMP_DECLARE_GENERATION(CoordinatorEpoch);

#undef ECMP_DECLARE_GENERATION

}  // namespace ecmp
