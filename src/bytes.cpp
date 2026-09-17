#include "ecmp/bytes.hpp"

#include <cstring>

namespace ecmp {

Encoder::Encoder(std::size_t max_blob_bytes) noexcept : max_blob_bytes_(max_blob_bytes) {
  data_.reserve(256);
}

void Encoder::u8(std::uint8_t value) { data_.push_back(value); }

void Encoder::u16(std::uint16_t value) {
  data_.push_back(static_cast<std::uint8_t>(value & 0xFFu));
  data_.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
}

void Encoder::u32(std::uint32_t value) {
  for (int shift = 0; shift < 32; shift += 8) {
    data_.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
  }
}

void Encoder::u64(std::uint64_t value) {
  for (int shift = 0; shift < 64; shift += 8) {
    data_.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
  }
}

void Encoder::i64(std::int64_t value) { u64(static_cast<std::uint64_t>(value)); }

void Encoder::boolean(bool value) { u8(value ? 1u : 0u); }

void Encoder::raw(std::span<const std::uint8_t> bytes) {
  data_.insert(data_.end(), bytes.begin(), bytes.end());
}

void Encoder::blob(std::span<const std::uint8_t> bytes) {
  if (bytes.size() > max_blob_bytes_) {
    failed_ = true;
    return;
  }
  u32(static_cast<std::uint32_t>(bytes.size()));
  raw(bytes);
}

void Encoder::text(std::string_view value) {
  if (value.size() > max_blob_bytes_) {
    failed_ = true;
    return;
  }
  u32(static_cast<std::uint32_t>(value.size()));
  data_.insert(data_.end(), value.begin(), value.end());
}

void Encoder::fixed16(std::span<const std::uint8_t, 16> bytes) {
  data_.insert(data_.end(), bytes.begin(), bytes.end());
}

std::vector<std::uint8_t> Encoder::take() {
  std::vector<std::uint8_t> out;
  out.swap(data_);
  return out;
}

Decoder::Decoder(std::span<const std::uint8_t> data, std::size_t max_blob_bytes) noexcept
    : data_(data), max_blob_bytes_(max_blob_bytes) {}

bool Decoder::require(std::size_t count) {
  if (failed_) {
    return false;
  }
  if (count > data_.size() - position_) {
    failed_ = true;
    return false;
  }
  return true;
}

bool Decoder::u8(std::uint8_t& out) {
  if (!require(1)) {
    return false;
  }
  out = data_[position_];
  position_ += 1;
  return true;
}

bool Decoder::u16(std::uint16_t& out) {
  if (!require(2)) {
    return false;
  }
  out = static_cast<std::uint16_t>(data_[position_]) |
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(data_[position_ + 1]) << 8);
  position_ += 2;
  return true;
}

bool Decoder::u32(std::uint32_t& out) {
  if (!require(4)) {
    return false;
  }
  out = 0;
  for (int index = 0; index < 4; ++index) {
    out |= static_cast<std::uint32_t>(data_[position_ + static_cast<std::size_t>(index)])
           << (8 * index);
  }
  position_ += 4;
  return true;
}

bool Decoder::u64(std::uint64_t& out) {
  if (!require(8)) {
    return false;
  }
  out = 0;
  for (int index = 0; index < 8; ++index) {
    out |= static_cast<std::uint64_t>(data_[position_ + static_cast<std::size_t>(index)])
           << (8 * index);
  }
  position_ += 8;
  return true;
}

bool Decoder::i64(std::int64_t& out) {
  std::uint64_t raw = 0;
  if (!u64(raw)) {
    return false;
  }
  out = static_cast<std::int64_t>(raw);
  return true;
}

bool Decoder::boolean(bool& out) {
  std::uint8_t raw = 0;
  if (!u8(raw)) {
    return false;
  }
  if (raw > 1) {
    failed_ = true;
    return false;
  }
  out = raw == 1;
  return true;
}

bool Decoder::raw(std::span<std::uint8_t> out) {
  if (!require(out.size())) {
    return false;
  }
  std::memcpy(out.data(), data_.data() + position_, out.size());
  position_ += out.size();
  return true;
}

bool Decoder::blob(std::vector<std::uint8_t>& out, std::size_t limit) {
  std::uint32_t length = 0;
  if (!u32(length)) {
    return false;
  }
  const std::size_t effective = limit < max_blob_bytes_ ? limit : max_blob_bytes_;
  if (length > effective) {
    failed_ = true;
    return false;
  }
  if (!require(length)) {
    return false;
  }
  out.assign(data_.begin() + static_cast<std::ptrdiff_t>(position_),
             data_.begin() + static_cast<std::ptrdiff_t>(position_ + length));
  position_ += length;
  return true;
}

bool Decoder::text(std::string& out, std::size_t limit) {
  std::uint32_t length = 0;
  if (!u32(length)) {
    return false;
  }
  const std::size_t effective = limit < max_blob_bytes_ ? limit : max_blob_bytes_;
  if (length > effective) {
    failed_ = true;
    return false;
  }
  if (!require(length)) {
    return false;
  }
  out.assign(reinterpret_cast<const char*>(data_.data() + position_), length);
  position_ += length;
  return true;
}

bool Decoder::fixed16(std::span<std::uint8_t, 16> out) {
  if (!require(16)) {
    return false;
  }
  std::memcpy(out.data(), data_.data() + position_, 16);
  position_ += 16;
  return true;
}

bool Decoder::skip(std::size_t count) {
  if (!require(count)) {
    return false;
  }
  position_ += count;
  return true;
}

}  // namespace ecmp
