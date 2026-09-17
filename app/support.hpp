#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "ecmp/governor.hpp"
#include "ecmp/server.hpp"
#include "ecmp/synthetic.hpp"

namespace ecmp::app {

// SYNTHETIC file-backed stand-in for the Path Authority and Multipath Fabric
// domains.  ECMP Governor 1.0.0 does not have those runtimes available on the
// build host, so the distributed proofs supply this clearly labelled synthetic
// view.  File format (LF separated, '#' starts a comment):
//
//   authority <path-hex32> <generation> <0|1>
//   multipath <set-hex32> <generation>
//   member    <set-hex32> <path-hex32>
//
// The coordinator loads the file once at start-up and then maintains the view in
// memory: upstream facts arriving over the wire are applied to the view before the
// governor re-observes, so the governor always reacts to an observation.
class SyntheticUpstreamView final : public IPathAuthorityView,
                                    public IMultipathSetView,
                                    public UpstreamNoticeHook {
 public:
  SyntheticUpstreamView() = default;

  [[nodiscard]] bool load(const std::filesystem::path& path, std::string& error);

  [[nodiscard]] std::optional<PathAuthorityObservation> observe(
      const PathId& path) const override;
  [[nodiscard]] std::optional<MultipathSetGeneration> generation(
      const MultipathSetId& set) const override;
  [[nodiscard]] bool contains(const MultipathSetId& set, MultipathSetGeneration generation,
                              const PathId& path) const override;

  void on_path_authority_change(const PathAuthorityChangeNotice& notice) override;
  void on_multipath_set_change(const MultipathSetChangeNotice& notice) override;
  void on_cost_generation_change(const CostGenerationChangeNotice& notice) override;

  void set_path(const PathId& path, PathAuthorityGeneration generation, bool authorized);
  void set_multipath(const MultipathSetId& set, MultipathSetGeneration generation,
                     std::set<PathId> members);
  [[nodiscard]] std::size_t path_count() const;
  [[nodiscard]] std::size_t set_count() const;

 private:
  struct SetEntry {
    MultipathSetGeneration generation;
    std::set<PathId> members;
  };

  mutable std::mutex mutex_;
  std::map<PathId, PathAuthorityObservation> paths_;
  std::map<MultipathSetId, SetEntry> sets_;
};

// Deterministic command line helpers shared by the applications.
[[nodiscard]] std::optional<std::string> find_option(const std::vector<std::string>& arguments,
                                                     const std::string& name);
[[nodiscard]] std::uint64_t option_u64(const std::vector<std::string>& arguments,
                                       const std::string& name, std::uint64_t fallback);
[[nodiscard]] bool has_flag(const std::vector<std::string>& arguments, const std::string& name);

}  // namespace ecmp::app
