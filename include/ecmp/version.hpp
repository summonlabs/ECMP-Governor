#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace ecmp {

inline constexpr std::string_view kProductName = "ECMP Governor";
inline constexpr std::string_view kVendorName = "Summon Software Labs";
inline constexpr std::string_view kLicenseNotice =
    "Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.";

inline constexpr std::uint32_t kVersionMajor = 1;
inline constexpr std::uint32_t kVersionMinor = 0;
inline constexpr std::uint32_t kVersionPatch = 0;
inline constexpr std::string_view kVersionString = "1.0.0";

// Representation versions.  These are deliberately independent of the product
// version: a product release does not change them, and changing one of them does
// not by itself change the product version.
inline constexpr std::uint32_t kWireVersion = 1;
inline constexpr std::uint32_t kPersistenceFormatVersion = 1;
inline constexpr std::uint32_t kDigestEncodingVersion = 1;
inline constexpr std::uint32_t kAssignmentAlgorithmVersion = 1;

// Deterministic multi-line version report with LF line endings.
[[nodiscard]] std::string version_report();

// Single-line form suitable for scripts: "ecmp-governor 1.0.0".
[[nodiscard]] std::string version_line();

}  // namespace ecmp
