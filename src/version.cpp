#include "ecmp/version.hpp"

#include <string>

namespace ecmp {

std::string version_line() {
  std::string out(kProductName);
  out += ' ';
  out += kVersionString;
  return out;
}

std::string version_report() {
  std::string out;
  out += "product: ";
  out += kProductName;
  out += '\n';
  out += "vendor: ";
  out += kVendorName;
  out += '\n';
  out += "version: ";
  out += kVersionString;
  out += '\n';
  out += "wire_version: " + std::to_string(kWireVersion) + "\n";
  out += "persistence_format_version: " + std::to_string(kPersistenceFormatVersion) + "\n";
  out += "digest_encoding_version: " + std::to_string(kDigestEncodingVersion) + "\n";
  out += "assignment_algorithm_version: " + std::to_string(kAssignmentAlgorithmVersion) + "\n";
  out += "license: ";
  out += kLicenseNotice;
  out += '\n';
  return out;
}

}  // namespace ecmp
