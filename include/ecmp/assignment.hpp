#pragma once

#include <compare>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include "ecmp/digest.hpp"
#include "ecmp/identity.hpp"
#include "ecmp/outcome.hpp"

namespace ecmp {

// Why one bucket changed owner.  Every move carries its reason so that an
// operator can ask "why did bucket 17 move from A to B" and get an exact answer
// instead of a whole-map replacement.
enum class MoveReason : std::uint32_t {
  INITIAL_ASSIGNMENT = 1,
  OWNER_REMOVED = 2,
  OWNER_OVER_QUOTA = 3,
};

[[nodiscard]] std::string_view to_string(MoveReason reason) noexcept;

struct BucketMove {
  BucketId bucket;
  ECMPMemberId from;  // nil when the bucket had no owner before this change
  ECMPMemberId to;
  MoveReason reason = MoveReason::INITIAL_ASSIGNMENT;

  friend bool operator==(const BucketMove&, const BucketMove&) = default;
  friend auto operator<=>(const BucketMove&, const BucketMove&) noexcept = default;
};

// Authoritative deterministic bucket assignment over [0, bucket_count).
// owners[b] is the single owner of bucket b; a nil owner means "no owner", which
// is legal only when the group has no active members.
struct BucketAssignment {
  BucketCount count;
  std::vector<ECMPMemberId> owners;

  [[nodiscard]] bool is_sized() const noexcept { return owners.size() == count.value(); }
  [[nodiscard]] std::uint32_t owned_bucket_count(const ECMPMemberId& member) const noexcept;

  // Assignment digest: depends only on the bucket count and the owner vector, so
  // the same bucket map hashes identically no matter how it was constructed.
  [[nodiscard]] Digest digest() const;

  friend bool operator==(const BucketAssignment&, const BucketAssignment&) = default;
};

// Pure result of the assignment algorithm.
struct RebalanceComputation {
  BucketAssignment assignment;
  std::vector<BucketMove> moves;  // ascending bucket order
  std::uint64_t retained_buckets = 0;

  [[nodiscard]] std::uint64_t churn() const noexcept {
    return static_cast<std::uint64_t>(moves.size());
  }
};

// Near-equal split of `bucket_count` buckets over `member_count` members in
// canonical order: the first (bucket_count % member_count) members receive one
// extra bucket.  The difference between the largest and the smallest share is at
// most one whenever bucket_count >= member_count.
[[nodiscard]] std::vector<std::uint32_t> balanced_bucket_counts(std::uint32_t bucket_count,
                                                               std::uint32_t member_count);

// Deterministic initial assignment from an empty state.  `canonical_members`
// must already be in the caller's canonical order.
[[nodiscard]] RebalanceComputation compute_initial_assignment(
    std::span<const ECMPMemberId> canonical_members, BucketCount count);

// Deterministic minimum-churn rebalance.
//
// Guarantee (proved and oracle-checked in the test suite): the number of buckets
// whose owner changes equals the information-theoretic minimum for the given
// previous assignment and new member set, that is
//   churn = bucket_count - sum over members of min(previous_share, target_share).
// Among all minimum-churn assignments the result is the lexicographically
// smallest owner vector, comparing bucket by bucket in ascending bucket order
// and members by their index in `canonical_members`.  The result depends only
// on (previous assignment, canonical member list, bucket count) - never on
// arrival order, wall clock, iteration order of unordered containers, or thread
// scheduling.
[[nodiscard]] RebalanceComputation compute_rebalance(
    const BucketAssignment& previous, std::span<const ECMPMemberId> canonical_members,
    BucketCount count);

// Minimum churn implied by the guarantee above; the test oracle compares the
// production rebalance against this independently derived value.
[[nodiscard]] std::uint64_t minimum_possible_churn(const BucketAssignment& previous,
                                                  std::span<const ECMPMemberId> canonical_members);

enum class AssignmentDefect : std::uint32_t {
  NONE = 0,
  COUNT_MISMATCH = 1,
  DUPLICATE_MEMBER_INPUT = 2,
  UNKNOWN_OWNER = 3,
  UNASSIGNED_BUCKET = 4,
  UNBALANCED = 5,
};

[[nodiscard]] std::string_view to_string(AssignmentDefect defect) noexcept;

// Full structural validation of an assignment against an active member set.
// Checked in a fixed order so the reported defect is deterministic.
[[nodiscard]] AssignmentDefect check_assignment(const BucketAssignment& assignment,
                                               std::span<const ECMPMemberId> active_members);

}  // namespace ecmp
