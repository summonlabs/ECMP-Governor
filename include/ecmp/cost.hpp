#pragma once

#include <compare>
#include <cstdint>
#include <string>

#include "ecmp/identity.hpp"

namespace ecmp {

// Deterministic bounded cost value.  No floating point is used anywhere in ECMP
// Governor: cost is an exact scaled integer pair and equality is exact field
// equality, so two costs are equal only when they are bit-for-bit identical in
// representation.  Values with different scales are never silently compared.
struct PathCost {
  std::int64_t units = 0;
  std::uint32_t scale = 0;  // decimal digits, bounded by kMaxScale

  static constexpr std::uint32_t kMaxScale = 9;

  [[nodiscard]] bool is_well_formed() const noexcept { return scale <= kMaxScale; }
  [[nodiscard]] std::string to_text() const;

  friend auto operator<=>(const PathCost&, const PathCost&) noexcept = default;
  friend bool operator==(const PathCost&, const PathCost&) noexcept = default;
};

// Provenance of the cost computation itself.  Equal numeric cost under two
// different cost models, policy generations or route classes never implies
// equal-cost membership.
struct CostModelBinding {
  CostModelId model;
  std::uint32_t model_version = 0;
  RouteClassId route_class;
  CostPolicyGeneration policy_generation;

  [[nodiscard]] bool is_well_formed() const noexcept {
    return !model.is_nil() && !route_class.is_nil();
  }

  friend auto operator<=>(const CostModelBinding&, const CostModelBinding&) noexcept = default;
  friend bool operator==(const CostModelBinding&, const CostModelBinding&) noexcept = default;
};

// A complete cost claim for one exact path: the value, the semantics it was
// computed under, and the source that produced it.
struct CostClaim {
  CostClassId cost_class;
  CostModelBinding binding;
  PathCost cost;
  ProvenanceId source;

  [[nodiscard]] bool is_well_formed() const noexcept {
    return !cost_class.is_nil() && binding.is_well_formed() && cost.is_well_formed() &&
           !source.is_nil();
  }

  friend bool operator==(const CostClaim&, const CostClaim&) = default;
};

// Group level equal-cost semantics.  Every member of a group must prove equality
// under exactly this class and this model binding.
struct CostSemantics {
  CostClassId cost_class;
  CostModelBinding binding;

  [[nodiscard]] bool is_well_formed() const noexcept {
    return !cost_class.is_nil() && binding.is_well_formed();
  }

  friend auto operator<=>(const CostSemantics&, const CostSemantics&) noexcept = default;
  friend bool operator==(const CostSemantics&, const CostSemantics&) noexcept = default;
};

// Result of comparing one claim against group semantics.  Kept separate from the
// mutation outcome so that cost diagnosis is testable on its own.
enum class CostCompatibility : std::uint32_t {
  EQUAL = 0,
  CLASS_MISMATCH = 1,
  MODEL_MISMATCH = 2,
  POLICY_STALE = 3,
  VALUE_MISMATCH = 4,
};

[[nodiscard]] std::string_view to_string(CostCompatibility compatibility) noexcept;

// The single authoritative equality rule.  `reference` is the cost value the
// group currently holds; the first member establishes it.
[[nodiscard]] CostCompatibility compare_cost_claim(const CostSemantics& semantics,
                                                   const PathCost& reference,
                                                   const CostClaim& claim) noexcept;

}  // namespace ecmp
