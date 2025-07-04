#include <des_key.hxx>
#include <array>
#include <bitset>
#include <cstdint>
#include <random>
#include <stdexcept>

des_key::des_key(const std::uint64_t& _key_u64,
  const std::array<uint8_t, 56>& _ip_table,
  const std::array<std::uint8_t, 16>& _cls_table,
  const std::array<uint8_t, 48>& _cp_table)
  : key_u64(_key_u64),
    key_bits(std::bitset<64>(_key_u64)),
    ip_table(_ip_table),
    cls_table(_cls_table),
    cp_table(_cp_table),
    key_list(this->des_key::gen_key_list()) {}

des_key::des_key(std::uint64_t&& _key_u64,
  const std::array<uint8_t, 56>& _ip_table,
  const std::array<std::uint8_t, 16>& _cls_table,
  const std::array<uint8_t, 48>& _cp_table)
  : key_u64(std::move(_key_u64)),
    key_bits(std::bitset<64>(_key_u64)),
    ip_table(_ip_table),
    cls_table(_cls_table),
    cp_table(_cp_table),
    key_list(this->des_key::gen_key_list()) {}

des_key::des_key(std::uint64_t&& _key_u64,
  std::array<uint8_t, 56>&& _ip_table,
  std::array<std::uint8_t, 16>&& _cls_table,
  std::array<uint8_t, 48>&& _cp_table)
  : key_u64(std::move(_key_u64)),
    key_bits(std::bitset<64>(std::move(_key_u64))),
    ip_table(std::move(_ip_table)),
    cls_table(std::move(_cls_table)),
    cp_table(std::move(_cp_table)),
    key_list(this->des_key::gen_key_list()) {}

des_key::des_key(const std::string& _str_key,
  const std::array<uint8_t, 56>& _ip_table,
  const std::array<std::uint8_t, 16>& _cls_table,
  const std::array<uint8_t, 48>& _cp_table)
  : des_key(string_to_uint64(_str_key), _ip_table, _cls_table, _cp_table) {} 

des_key::des_key(std::string&& _str_key,
  const std::array<uint8_t, 56>& _ip_table,
  const std::array<std::uint8_t, 16>& _cls_table,
  const std::array<uint8_t, 48>& _cp_table)
  : des_key(string_to_uint64(std::move(_str_key)), _ip_table, _cls_table, _cp_table) {} 

des_key::des_key(std::string&& _str_key,
  std::array<uint8_t, 56>&& _ip_table,
  std::array<std::uint8_t, 16>&& _cls_table,
  std::array<uint8_t, 48>&& _cp_table)
  : des_key(string_to_uint64(std::move(_str_key)), std::move(_ip_table), std::move(_cls_table), std::move(_cp_table)) {} 

std::uint64_t des_key::string_to_uint64(const std::string& str) {
  if (str.size() != 8) throw std::invalid_argument("[ERROR] String key must be exactly 8 characters");
  return std::accumulate(str.begin(), str.end(), std::uint64_t{0},
    [](std::uint64_t acc, char c) {
      return (acc << 8) | static_cast<std::uint8_t>(c); 
    });}

std::uint64_t des_key::string_to_uint64(std::string&& str) {
  if (str.size() != 8) throw std::invalid_argument("[ERROR] String key must be exactly 8 characters");
  return std::accumulate(str.begin(), str.end(), std::uint64_t{0},
    [](std::uint64_t acc, char c) {
      return (acc << 8) | static_cast<std::uint8_t>(c); 
    });}

std::array<uint8_t, 56> des_key::key_initial_permutation_table_gen() {
  std::array<uint8_t, 56> result;
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint16_t> dist(1, 64);
  for (uint8_t i{0}; i < 56; ++i) result[i] = static_cast<uint8_t>(dist(gen));
  return result;
}

std::array<std::uint8_t, 16> des_key::key_circular_left_shifted_table_gen() {
  std::array<std::uint8_t, 16> result;
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint16_t> dist(1, 28);
  for (uint8_t i{0}; i < 16; ++i) result[i] = static_cast<uint8_t>(dist(gen));
  return result;
}

std::array<uint8_t, 48> des_key::key_compression_permutation_table_gen() {
  std::array<uint8_t, 48> result;
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint16_t> dist(1, 56);
  for (uint8_t i{0}; i < 48; ++i) result[i] = static_cast<uint8_t>(dist(gen));
  return result;
}

std::bitset<56> des_key::key_initial_permutation(std::bitset<64> key) {
  std::bitset<56> result;
  for (uint8_t i{0}; i < 56; ++i) result[55-i] = key[64-this->ip_table[i]];
  return result;
}

std::bitset<56> des_key::key_circular_shifted_left(std::bitset<56> key, std::uint8_t shift) {
  if (shift > 28 || shift < 1) [[unlikely]] throw std::invalid_argument("rotattion size should be in range [1, 28]");
  std::bitset<28> c, d;
  for (uint8_t i{0}; i < 28; ++i) c[i] = key[28+i], d[i] = key[i];
  c = (c << shift) | (c >> (28 - shift)), d = (d << shift) | (d >> (28 - shift));
  std::bitset<56> result = (std::bitset<56>(c.to_ullong()) << 28) | (std::bitset<56>(d.to_ullong()));
  return result;
}

std::bitset<48> des_key::key_compression_permutation(std::bitset<56> key) {
  std::bitset<48> result;
  for (uint8_t i{0}; i < 48; ++i) result[47-i] = key[56-this->cp_table[i]];
  return result;
}

std::array<std::bitset<48>, 16> des_key::gen_key_list() {
  std::array<std::bitset<48>, 16> result;
  std::bitset<56> key_56_s; 
    std::bitset<56> key_56 = this->des_key::key_initial_permutation(this->des_key::key_bits);
  for (std::uint8_t i{0}; i < 16; ++i) {
    key_56_s = this->des_key::key_circular_shifted_left(i == 0? key_56: key_56_s, this->des_key::cls_table[i]);
    result[i] = key_compression_permutation(key_56_s);
  }
  return result;
}
