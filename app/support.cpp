#include "support.hpp"

#include <fstream>
#include <sstream>
#include <string>

#include "ecmp/digest.hpp"

namespace ecmp::app {
namespace {

bool parse_u64(const std::string& text, std::uint64_t& out) {
  if (text.empty()) {
    return false;
  }
  std::uint64_t value = 0;
  for (const char character : text) {
    if (character < '0' || character > '9') {
      return false;
    }
    const std::uint64_t digit = static_cast<std::uint64_t>(character - '0');
    if (value > (0xFFFFFFFFFFFFFFFFull - digit) / 10ull) {
      return false;
    }
    value = (value * 10ull) + digit;
  }
  out = value;
  return true;
}

}  // namespace

bool SyntheticUpstreamView::load(const std::filesystem::path& path, std::string& error) {
  std::ifstream in(path);
  if (!in) {
    error = "cannot open authority view file";
    return false;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  std::string line;
  std::uint64_t line_number = 0;
  while (std::getline(in, line)) {
    ++line_number;
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    const std::size_t comment = line.find('#');
    if (comment != std::string::npos) {
      line.erase(comment);
    }
    std::istringstream stream(line);
    std::string keyword;
    if (!(stream >> keyword)) {
      continue;
    }
    if (keyword == "authority") {
      std::string path_text;
      std::string generation_text;
      std::string authorized_text;
      if (!(stream >> path_text >> generation_text >> authorized_text)) {
        error = "malformed authority line " + std::to_string(line_number);
        return false;
      }
      const auto authority_path = PathId::parse(path_text);
      std::uint64_t generation = 0;
      if (!authority_path.has_value() || !parse_u64(generation_text, generation) ||
          (authorized_text != "0" && authorized_text != "1")) {
        error = "malformed authority line " + std::to_string(line_number);
        return false;
      }
      PathAuthorityObservation observation;
      observation.generation = PathAuthorityGeneration::from_value(generation);
      observation.authorized = authorized_text == "1";
      paths_[*authority_path] = observation;
      continue;
    }
    if (keyword == "multipath") {
      std::string set_text;
      std::string generation_text;
      if (!(stream >> set_text >> generation_text)) {
        error = "malformed multipath line " + std::to_string(line_number);
        return false;
      }
      const auto set = MultipathSetId::parse(set_text);
      std::uint64_t generation = 0;
      if (!set.has_value() || !parse_u64(generation_text, generation)) {
        error = "malformed multipath line " + std::to_string(line_number);
        return false;
      }
      sets_[*set].generation = MultipathSetGeneration::from_value(generation);
      continue;
    }
    if (keyword == "member") {
      std::string set_text;
      std::string member_path_text;
      if (!(stream >> set_text >> member_path_text)) {
        error = "malformed member line " + std::to_string(line_number);
        return false;
      }
      const auto set = MultipathSetId::parse(set_text);
      const auto member_path = PathId::parse(member_path_text);
      if (!set.has_value() || !member_path.has_value()) {
        error = "malformed member line " + std::to_string(line_number);
        return false;
      }
      sets_[*set].members.insert(*member_path);
      continue;
    }
    error = "unknown authority view keyword on line " + std::to_string(line_number);
    return false;
  }
  return true;
}

std::optional<PathAuthorityObservation> SyntheticUpstreamView::observe(
    const PathId& path) const {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto it = paths_.find(path);
  if (it == paths_.end()) {
    return std::nullopt;
  }
  return it->second;
}

std::optional<MultipathSetGeneration> SyntheticUpstreamView::generation(
    const MultipathSetId& set) const {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto it = sets_.find(set);
  if (it == sets_.end()) {
    return std::nullopt;
  }
  return it->second.generation;
}

bool SyntheticUpstreamView::contains(const MultipathSetId& set, MultipathSetGeneration generation,
                                     const PathId& path) const {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto it = sets_.find(set);
  if (it == sets_.end() || !(it->second.generation == generation)) {
    return false;
  }
  return it->second.members.count(path) != 0;
}

void SyntheticUpstreamView::on_path_authority_change(const PathAuthorityChangeNotice& notice) {
  std::lock_guard<std::mutex> lock(mutex_);
  PathAuthorityObservation observation;
  observation.generation = notice.generation;
  observation.authorized = true;
  paths_[notice.path] = observation;
}

void SyntheticUpstreamView::on_multipath_set_change(const MultipathSetChangeNotice& notice) {
  std::lock_guard<std::mutex> lock(mutex_);
  sets_[notice.set].generation = notice.generation;
}

void SyntheticUpstreamView::on_cost_generation_change(const CostGenerationChangeNotice&) {}

void SyntheticUpstreamView::set_path(const PathId& path, PathAuthorityGeneration generation,
                                     bool authorized) {
  std::lock_guard<std::mutex> lock(mutex_);
  PathAuthorityObservation observation;
  observation.generation = generation;
  observation.authorized = authorized;
  paths_[path] = observation;
}

void SyntheticUpstreamView::set_multipath(const MultipathSetId& set,
                                          MultipathSetGeneration generation,
                                          std::set<PathId> members) {
  std::lock_guard<std::mutex> lock(mutex_);
  SetEntry entry;
  entry.generation = generation;
  entry.members = std::move(members);
  sets_[set] = std::move(entry);
}

std::size_t SyntheticUpstreamView::path_count() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return paths_.size();
}

std::size_t SyntheticUpstreamView::set_count() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return sets_.size();
}

std::optional<std::string> find_option(const std::vector<std::string>& arguments,
                                       const std::string& name) {
  for (std::size_t index = 0; index + 1 < arguments.size(); ++index) {
    if (arguments[index] == name) {
      return arguments[index + 1];
    }
  }
  return std::nullopt;
}

std::uint64_t option_u64(const std::vector<std::string>& arguments, const std::string& name,
                         std::uint64_t fallback) {
  const std::optional<std::string> text = find_option(arguments, name);
  if (!text.has_value()) {
    return fallback;
  }
  std::uint64_t value = 0;
  if (!parse_u64(*text, value)) {
    return fallback;
  }
  return value;
}

bool has_flag(const std::vector<std::string>& arguments, const std::string& name) {
  for (const std::string& argument : arguments) {
    if (argument == name) {
      return true;
    }
  }
  return false;
}

}  // namespace ecmp::app
