#include <cstdint>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <string>
#include <vector>

#include "ecmp/ecmp.hpp"
#include "ecmp/server.hpp"
#include "ecmp/version.hpp"
#include "support.hpp"

namespace {

void usage() {
  std::printf(
      "usage: ecmp_coordinator --store <path> [--port N] [--authority-view FILE]\n"
      "                        [--no-autosave] [--max-requests N]\n"
      "\n"
      "The coordinator is the single authoritative ECMP Governor for one durable\n"
      "store.  It is not a consensus service: stale epochs are fenced by epoch\n"
      "comparison and exactly one coordinator owns the store at a time.\n");
}

}  // namespace

int main(int argc, char** argv) {
  std::vector<std::string> arguments;
  for (int index = 1; index < argc; ++index) {
    arguments.emplace_back(argv[index]);
  }
  if (arguments.empty() || ecmp::app::has_flag(arguments, "--help")) {
    usage();
    return arguments.empty() ? 2 : 0;
  }
  try {
    const std::optional<std::string> store_option = ecmp::app::find_option(arguments, "--store");
    if (!store_option.has_value()) {
      std::printf("ECMP_COORDINATOR_ERROR detail=store_path_required\n");
      return 2;
    }
    const std::filesystem::path store_path = *store_option;

    ecmp::app::SyntheticUpstreamView view;
    const std::optional<std::string> view_option =
        ecmp::app::find_option(arguments, "--authority-view");
    if (view_option.has_value()) {
      std::string error;
      if (!view.load(*view_option, error)) {
        std::printf("ECMP_COORDINATOR_ERROR detail=%s\n", error.c_str());
        return 1;
      }
    }

    ecmp::GovernorLimits limits;
    ecmp::EcmpGovernor governor(limits, ecmp::CoordinatorEpoch::from_value(1), &view, &view);

    std::uint32_t recovered = 0;
    std::error_code exists_error;
    if (std::filesystem::exists(store_path, exists_error)) {
      const ecmp::LoadReport report = governor.load(store_path);
      if (!report.ok) {
        std::printf("ECMP_COORDINATOR_ERROR detail=load_failed:%s\n", report.detail.c_str());
        return 1;
      }
      const std::optional<ecmp::CoordinatorEpoch> next = report.stored_epoch.next();
      if (!next.has_value()) {
        std::printf("ECMP_COORDINATOR_ERROR detail=epoch_exhausted\n");
        return 1;
      }
      ecmp::ConditionList conditions(limits.max_explanation_entries);
      if (!governor.set_epoch(*next, conditions)) {
        std::printf("ECMP_COORDINATOR_ERROR detail=epoch_advance_rejected\n");
        return 1;
      }
      recovered = report.groups_loaded;
    }
    // The epoch advance is persisted before the coordinator serves a single
    // request, so a second restart always observes a strictly larger epoch.
    const ecmp::SaveReport saved = governor.save(store_path);
    if (!saved.ok) {
      std::printf("ECMP_COORDINATOR_ERROR detail=store_write_failed:%s\n", saved.detail.c_str());
      return 1;
    }

    ecmp::CoordinatorServerOptions options;
    options.port = static_cast<std::uint16_t>(ecmp::app::option_u64(arguments, "--port", 0));
    options.store_path = store_path;
    options.autosave = !ecmp::app::has_flag(arguments, "--no-autosave");
    options.upstream_hook = &view;
    options.max_requests = ecmp::app::option_u64(arguments, "--max-requests", 0);

    ecmp::CoordinatorServer server(governor, options);
    std::string error;
    if (!server.start(error)) {
      std::printf("ECMP_COORDINATOR_ERROR detail=bind_failed:%s\n", error.c_str());
      return 1;
    }
    std::printf(
        "ECMP_COORDINATOR_READY product=%s version=%s wire=%u persistence=%u port=%u epoch=%llu "
        "recovered_groups=%u authority_paths=%llu\n",
        std::string(ecmp::kProductName).c_str(), std::string(ecmp::kVersionString).c_str(),
        ecmp::kWireVersion, ecmp::kPersistenceFormatVersion, server.port(),
        static_cast<unsigned long long>(governor.epoch().value()), recovered,
        static_cast<unsigned long long>(view.path_count()));
    std::fflush(stdout);

    server.serve();

    const ecmp::GovernorStatistics statistics = governor.statistics();
    std::printf("ECMP_COORDINATOR_STOPPED requests=%llu groups=%llu\n",
                static_cast<unsigned long long>(server.handled_requests()),
                static_cast<unsigned long long>(statistics.groups));
    std::fflush(stdout);
    return 0;
  } catch (const std::exception& exception) {
    std::printf("ECMP_COORDINATOR_ERROR detail=exception:%s\n", exception.what());
    std::fflush(stdout);
    return 1;
  }
}
