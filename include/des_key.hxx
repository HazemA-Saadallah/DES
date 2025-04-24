#pragma once

#include <array>
#include <bitset>
#include <cstdint>
#include <string>
#include <optional>

class des_key {
  std::bitset<56> key_initial_permutation(std::bitset<64>);
  std::bitset<56> key_circular_shifted_left(std::bitset<56>, std::uint8_t);
  std::bitset<48> key_compression_permutation(std::bitset<56>);
  std::array<std::bitset<48>, 16> gen_key_list();

  public:
    des_key(std::string,
      std::optional<std::array<uint8_t, 56>> = std::nullopt,
      std::optional<std::array<std::uint8_t, 16>> = std::nullopt,
      std::optional<std::array<uint8_t, 48>> = std::nullopt);

    des_key(std::uint64_t,
      std::optional<std::array<uint8_t, 56>> = std::nullopt,
      std::optional<std::array<std::uint8_t, 16>> = std::nullopt,
      std::optional<std::array<uint8_t, 48>> = std::nullopt);

    const std::uint64_t key_u64;
    const std::bitset<64> key_bits;
    const std::array<uint8_t, 56> ip_table;
    const std::array<std::uint8_t, 16>cls_table;
    const std::array<uint8_t, 48> cp_table;
    const std::array<std::bitset<48>, 16> key_list;

    static std::array<uint8_t, 56> key_initial_permutation_table_gen();
    static std::array<std::uint8_t, 16> key_circular_left_shifted_table_gen();
    static std::array<uint8_t, 48> key_compression_permutation_table_gen();

    constexpr static const std::array<std::uint8_t, 56> STANDARD_IP_TALBLE = { 
      57, 49, 41, 33, 25, 17, 9,
      1,  58, 50, 42, 34, 26, 18,
      10,  2,  59, 51, 43, 35, 27,
      19, 11, 3,  60, 52, 44, 36,
      63, 55, 47, 39, 31, 23, 15,
      7,  62, 54, 46, 38, 30, 22,
      14, 6,  61, 53, 45, 37, 29,
      21, 13, 5,  28, 20, 12, 4
    };

    constexpr static const std::array<std::uint8_t, 16> STANDARD_CLS_TABLE = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
    constexpr static const std::array<uint8_t, 48> STANDARD_CP_TABLE = {
      14, 17, 11, 24, 1,  5,
      3,  28, 15, 6,  21, 10,
      23, 19, 12, 4,  26, 8,
      16, 7,  27, 20, 13, 2,
      41, 52, 31, 37, 47, 55,
      30, 40, 51, 45, 33, 48,
      44, 49, 39, 56, 34, 53,
      46, 42, 50, 36, 29, 32
    };
};
