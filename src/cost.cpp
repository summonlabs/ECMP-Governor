#include "ecmp/cost.hpp"

#include <string>

namespace ecmp {

std::string PathCost::to_text() const {
  const bool negative = units < 0;
  std::uint64_t magnitude = 0;
  if (negative) {
    magnitude = static_cast<std::uint64_t>(-(units + 1)) + 1u;
  } else {
    magnitude = static_cast<std::uint64_t>(units);
  }

  std::uint64_t divisor = 1;
  for (std::uint32_t index = 0; index < scale; ++index) {
    divisor *= 10u;
  }

  std::string out;
  if (negative) {
    out += '-';
  }
  out += std::to_string(magnitude / divisor);
  if (scale > 0) {
    out += '.';
    const std::string fraction = std::to_string(magnitude % divisor);
    out.append(static_cast<std::size_t>(scale) - fraction.size(), '0');
    out += fraction;
  }
  return out;
}

std::string_view to_string(CostCompatibility compatibility) noexcept {
  switch (compatibility) {
    case CostCompatibility::EQUAL: return "EQUAL";
    case CostCompatibility::CLASS_MISMATCH: return "CLASS_MISMATCH";
    case CostCompatibility::MODEL_MISMATCH: return "MODEL_MISMATCH";
    case CostCompatibility::POLICY_STALE: return "POLICY_STALE";
    case CostCompatibility::VALUE_MISMATCH: return "VALUE_MISMATCH";
  }
  return "UNKNOWN_COST_COMPATIBILITY";
}

CostCompatibility compare_cost_claim(const CostSemantics& semantics, const PathCost& reference,
                                    const CostClaim& claim) noexcept {
  if (claim.cost_class != semantics.cost_class) {
    return CostCompatibility::CLASS_MISMATCH;
  }
  if (claim.binding.model != semantics.binding.model ||
      claim.binding.model_version != semantics.binding.model_version ||
      claim.binding.route_class != semantics.binding.route_class) {
    return CostCompatibility::MODEL_MISMATCH;
  }
  if (claim.binding.policy_generation != semantics.binding.policy_generation) {
    return CostCompatibility::POLICY_STALE;
  }
  if (!(claim.cost == reference)) {
    return CostCompatibility::VALUE_MISMATCH;
  }
  return CostCompatibility::EQUAL;
}

}  // namespace ecmp
