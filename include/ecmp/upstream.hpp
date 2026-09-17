#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "ecmp/cost.hpp"
#include "ecmp/identity.hpp"

namespace ecmp {

// Observation of one exact path by the Path Authority domain.  ECMP Governor
// never decides legality itself: it consumes this observation and binds the
// exact generation it saw.  Path Authority remains the path-legality authority.
struct PathAuthorityObservation {
  PathAuthorityGeneration generation;
  bool authorized = false;
};

// Upstream integrations are narrow read-only views.  In 1.0.0 the proofs use
// synthetic implementations of these interfaces; wiring a real Path Authority or
// Multipath Fabric runtime is a matter of implementing the same two or three
// methods against that runtime.
class IPathAuthorityView {
 public:
  IPathAuthorityView() = default;
  virtual ~IPathAuthorityView() = default;
  IPathAuthorityView(const IPathAuthorityView&) = delete;
  IPathAuthorityView& operator=(const IPathAuthorityView&) = delete;
  IPathAuthorityView(IPathAuthorityView&&) = delete;
  IPathAuthorityView& operator=(IPathAuthorityView&&) = delete;

  // Returns std::nullopt when the path is unknown to the Path Authority domain.
  [[nodiscard]] virtual std::optional<PathAuthorityObservation> observe(
      const PathId& path) const = 0;
};

class IMultipathSetView {
 public:
  IMultipathSetView() = default;
  virtual ~IMultipathSetView() = default;
  IMultipathSetView(const IMultipathSetView&) = delete;
  IMultipathSetView& operator=(const IMultipathSetView&) = delete;
  IMultipathSetView(IMultipathSetView&&) = delete;
  IMultipathSetView& operator=(IMultipathSetView&&) = delete;

  // Current generation of the governed multipath set, or nullopt when unknown.
  [[nodiscard]] virtual std::optional<MultipathSetGeneration> generation(
      const MultipathSetId& set) const = 0;

  // True when the exact member is still part of the exact set generation.
  [[nodiscard]] virtual bool contains(const MultipathSetId& set, MultipathSetGeneration generation,
                                      const PathId& path) const = 0;
};

// A view that knows nothing.  Used as the explicit default so that a governor
// constructed without upstream wiring cannot silently validate anything.
class UnknownPathAuthorityView final : public IPathAuthorityView {
 public:
  [[nodiscard]] std::optional<PathAuthorityObservation> observe(
      const PathId& path) const override;
};

class UnknownMultipathSetView final : public IMultipathSetView {
 public:
  [[nodiscard]] std::optional<MultipathSetGeneration> generation(
      const MultipathSetId& set) const override;
  [[nodiscard]] bool contains(const MultipathSetId& set, MultipathSetGeneration generation,
                              const PathId& path) const override;
};

}  // namespace ecmp
