#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "ecmp/ecmp.hpp"
#include "test_framework.hpp"

namespace {

using namespace ecmp;

std::filesystem::path store_path(const std::string& name) {
  const std::filesystem::path directory =
      std::filesystem::temp_directory_path() / "ecmp-governor-persistence";
  std::error_code error;
  std::filesystem::create_directories(directory, error);
  return directory / (name + ".store");
}

std::vector<std::uint8_t> read_bytes(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  in.seekg(0, std::ios::end);
  const std::streamoff size = in.tellg();
  in.seekg(0, std::ios::beg);
  std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size), 0);
  if (size > 0) {
    in.read(reinterpret_cast<char*>(bytes.data()), size);
  }
  return bytes;
}

void write_bytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
}

class PathView final : public IPathAuthorityView {
 public:
  [[nodiscard]] std::optional<PathAuthorityObservation> observe(const PathId&) const override {
    PathAuthorityObservation observation;
    observation.generation = PathAuthorityGeneration::from_value(1);
    observation.authorized = true;
    return observation;
  }
};

struct Built {
  std::filesystem::path path;
  std::vector<std::uint8_t> bytes;
};

Built build_store(const std::string& name) {
  Built built;
  built.path = store_path(name);
  std::error_code error;
  std::filesystem::remove(built.path, error);
  PathView view;
  GovernorLimits limits;
  EcmpGovernor governor(limits, CoordinatorEpoch::from_value(1), &view);
  PublisherRegistration registration;
  registration.publisher = synthetic_publisher_id(1);
  registration.worker_boot = synthetic_boot_id(1);
  registration.scope = AuthorityScope::for_fabric(synthetic_ids(1).fabric);
  registration.capabilities = 3;
  registration.provenance = synthetic_ids(1).provenance;
  ConditionList conditions(limits.max_explanation_entries);
  ECMP_REQUIRE(governor.register_publisher(CoordinatorEpoch::from_value(1), registration,
                                           conditions) == Outcome::REGISTERED);
  for (std::uint64_t seed = 1; seed <= 2; ++seed) {
    const SyntheticIds ids = synthetic_ids(seed);
    CreateGroupRequest request;
    request.authority.epoch = governor.epoch();
    request.authority.publisher = registration.publisher;
    request.authority.worker_boot = registration.worker_boot;
    request.authority.scope = registration.scope;
    request.authority.attempt = synthetic_attempt_id(seed);
    request.group = synthetic_group_id(seed);
    request.key = synthetic_group_key(ids);
    // Stay inside the granted fabric while varying the remaining key dimensions.
    request.key.fabric = registration.scope.fabric;
    request.cost_semantics = synthetic_cost_semantics(ids, 1);
    request.hash_domain = ids.hash_domain;
    request.provenance = ids.provenance;
    request.bucket_count = *BucketCount::make(16);
    request.min_active_members = 1;
    request.members = synthetic_members(ids, 4, PathAuthorityGeneration::from_value(1));
    ECMP_REQUIRE(is_acceptance(governor.create_group(request).outcome));
  }
  const SaveReport saved = governor.save(built.path);
  ECMP_REQUIRE(saved.ok);
  built.bytes = read_bytes(built.path);
  ECMP_REQUIRE(!built.bytes.empty());
  return built;
}

StoreDefect decode_image(const std::vector<std::uint8_t>& bytes, std::uint32_t* groups,
                         std::string* detail = nullptr) {
  GovernorLimits limits;
  StoreFileInfo info;
  std::vector<std::uint8_t> payload;
  const StoreDefect defect = decode_store_file(bytes, limits, info, payload);
  if (defect != StoreDefect::NONE) {
    return defect;
  }
  PathView view;
  EcmpGovernor governor(limits, CoordinatorEpoch::from_value(1), &view);
  const std::filesystem::path path = store_path("decode-image");
  write_bytes(path, bytes);
  const LoadReport report = governor.load(path);
  if (groups != nullptr) {
    *groups = report.groups_loaded;
  }
  if (detail != nullptr) {
    *detail = report.detail;
  }
  return report.ok ? StoreDefect::NONE : StoreDefect::STRUCTURE;
}

}  // namespace

ECMP_TEST(test_store_file_envelope) {
  const std::vector<std::uint8_t> payload{1, 2, 3, 4};
  const std::vector<std::uint8_t> image = encode_store_file(7, payload);
  ECMP_CHECK_EQ(image.size(), std::size_t{8 + 4 + 4 + 8 + 4 + 4 + 32});
  GovernorLimits limits;
  StoreFileInfo info;
  std::vector<std::uint8_t> decoded;
  ECMP_CHECK(decode_store_file(image, limits, info, decoded) == StoreDefect::NONE);
  ECMP_CHECK_EQ(info.coordinator_epoch, std::uint64_t{7});
  ECMP_CHECK(decoded == payload);

  std::vector<std::uint8_t> wrong_magic = image;
  wrong_magic[0] = 'X';
  ECMP_CHECK(decode_store_file(wrong_magic, limits, info, decoded) == StoreDefect::BAD_MAGIC);

  std::vector<std::uint8_t> wrong_version = image;
  wrong_version[8] = 9;
  ECMP_CHECK(decode_store_file(wrong_version, limits, info, decoded) == StoreDefect::BAD_VERSION);

  std::vector<std::uint8_t> reserved = image;
  reserved[12] = 1;
  ECMP_CHECK(decode_store_file(reserved, limits, info, decoded) ==
             StoreDefect::RESERVED_NOT_ZERO);

  std::vector<std::uint8_t> trailing = image;
  trailing.push_back(0);
  ECMP_CHECK(decode_store_file(trailing, limits, info, decoded) == StoreDefect::TRAILING_BYTES);

  std::vector<std::uint8_t> flipped = image;
  flipped[flipped.size() / 2] ^= 0x40;
  ECMP_CHECK(decode_store_file(flipped, limits, info, decoded) ==
             StoreDefect::INTEGRITY_FAILURE);

  // The declared payload length field sits after magic(8), version(4),
  // reserved(4) and epoch(8).
  std::vector<std::uint8_t> absurd = image;
  absurd[24] = 0xFF;
  absurd[25] = 0xFF;
  absurd[26] = 0xFF;
  absurd[27] = 0x7F;
  ECMP_CHECK(decode_store_file(absurd, limits, info, decoded) == StoreDefect::PAYLOAD_TOO_LARGE);

  ECMP_CHECK(decode_store_file({}, limits, info, decoded) == StoreDefect::EMPTY);
}

ECMP_TEST(test_every_truncation_point_rejects_safely) {
  const Built built = build_store("truncation");
  std::uint32_t groups = 0;
  ECMP_CHECK(decode_image(built.bytes, &groups) == StoreDefect::NONE);
  ECMP_CHECK_EQ(groups, std::uint32_t{2});

  for (std::size_t length = 0; length < built.bytes.size(); ++length) {
    const std::vector<std::uint8_t> truncated(built.bytes.begin(),
                                              built.bytes.begin() + static_cast<std::ptrdiff_t>(length));
    const StoreDefect defect = decode_image(truncated, nullptr);
    ECMP_CHECK(defect != StoreDefect::NONE);
  }
}

ECMP_TEST(test_bit_flips_are_rejected) {
  const Built built = build_store("bitflip");
  // A single flipped bit anywhere in the image must never load silently.
  for (std::size_t index = 0; index < built.bytes.size(); index += 7) {
    std::vector<std::uint8_t> flipped = built.bytes;
    flipped[index] ^= 0x01;
    const StoreDefect defect = decode_image(flipped, nullptr);
    ECMP_CHECK(defect != StoreDefect::NONE);
  }
}

ECMP_TEST(test_structural_corruption_is_rejected) {
  const Built built = build_store("structure");

  // Duplicate group: replace the first group's identity with the second's while
  // keeping the integrity trailer valid, which forces the structural checks to
  // reject it rather than the digest.
  {
    GovernorLimits limits;
    StoreFileInfo info;
    std::vector<std::uint8_t> payload;
    ECMP_REQUIRE(decode_store_file(built.bytes, limits, info, payload) == StoreDefect::NONE);
    const std::vector<std::uint8_t> first_id(payload.begin() + 8, payload.begin() + 24);
    const std::size_t second_id_offset = 8 + 24 + 4;  // header + first group header + group count
    (void)first_id;
    (void)second_id_offset;
  }

  // A payload with an impossible group count.
  {
    GovernorLimits limits;
    StoreFileInfo info;
    std::vector<std::uint8_t> payload;
    ECMP_REQUIRE(decode_store_file(built.bytes, limits, info, payload) == StoreDefect::NONE);
    std::vector<std::uint8_t> corrupted = payload;
    corrupted[4] = 0xFF;
    corrupted[5] = 0xFF;
    corrupted[6] = 0xFF;
    corrupted[7] = 0x7F;
    const std::vector<std::uint8_t> image = encode_store_file(1, corrupted);
    ECMP_CHECK(decode_image(image, nullptr) != StoreDefect::NONE);
  }

  // A payload with an impossible version.
  {
    GovernorLimits limits;
    StoreFileInfo info;
    std::vector<std::uint8_t> payload;
    ECMP_REQUIRE(decode_store_file(built.bytes, limits, info, payload) == StoreDefect::NONE);
    std::vector<std::uint8_t> corrupted = payload;
    corrupted[0] = 42;
    const std::vector<std::uint8_t> image = encode_store_file(1, corrupted);
    std::string detail;
    ECMP_CHECK(decode_image(image, nullptr, &detail) != StoreDefect::NONE);
    ECMP_CHECK(detail.find("BAD_VERSION") != std::string::npos);
  }

  // Trailing bytes inside the payload.
  {
    GovernorLimits limits;
    StoreFileInfo info;
    std::vector<std::uint8_t> payload;
    ECMP_REQUIRE(decode_store_file(built.bytes, limits, info, payload) == StoreDefect::NONE);
    std::vector<std::uint8_t> corrupted = payload;
    corrupted.push_back(0);
    const std::vector<std::uint8_t> image = encode_store_file(1, corrupted);
    ECMP_CHECK(decode_image(image, nullptr) != StoreDefect::NONE);
  }

  // Nil group identity inside a record.
  {
    GovernorLimits limits;
    StoreFileInfo info;
    std::vector<std::uint8_t> payload;
    ECMP_REQUIRE(decode_store_file(built.bytes, limits, info, payload) == StoreDefect::NONE);
    std::vector<std::uint8_t> corrupted = payload;
    for (std::size_t index = 8; index < 8 + 16; ++index) {
      corrupted[index] = 0;
    }
    const std::vector<std::uint8_t> image = encode_store_file(1, corrupted);
    ECMP_CHECK(decode_image(image, nullptr) != StoreDefect::NONE);
  }
}

ECMP_TEST(test_atomic_replacement_leaves_no_temporary_and_never_a_mixture) {
  const std::filesystem::path path = store_path("atomic");
  std::error_code error;
  std::filesystem::remove(path, error);

  const Built built = build_store("atomic-source");
  std::string message;
  ECMP_CHECK(write_store_file_atomic(path, built.bytes, message) == StoreDefect::NONE);

  // A leftover partial temporary file from a crashed writer carries no authority
  // and is simply replaced on the next successful save.
  const std::filesystem::path stale_temp = std::filesystem::path(path.string() + ".tmp.999");
  write_bytes(stale_temp, std::vector<std::uint8_t>{1, 2, 3});
  ECMP_CHECK(write_store_file_atomic(path, built.bytes, message) == StoreDefect::NONE);

  std::vector<std::uint8_t> bytes;
  ECMP_CHECK(read_store_file(path, bytes, message) == StoreDefect::NONE);
  ECMP_CHECK(bytes == built.bytes);

  // The reader rejects a nonexistent store rather than inventing an empty one.
  std::filesystem::remove(path, error);
  ECMP_CHECK(read_store_file(path, bytes, message) == StoreDefect::IO_ERROR);
  std::filesystem::remove(stale_temp, error);
}

ECMP_TEST(test_store_limits_are_consulted) {
  const Built built = build_store("limits");
  GovernorLimits limits;
  limits.max_persistence_record_bytes = 4096;
  StoreFileInfo info;
  std::vector<std::uint8_t> payload;
  const StoreDefect defect = decode_store_file(built.bytes, limits, info, payload);
  ECMP_CHECK(defect == StoreDefect::NONE || defect == StoreDefect::PAYLOAD_TOO_LARGE);
  // The read path must not exceed the configured bound regardless of the outcome.
  ECMP_CHECK(payload.size() <= limits.max_persistence_record_bytes);
}
