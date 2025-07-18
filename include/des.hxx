#pragma once

#include <array>
#include <bitset>
#include <cstdint>
#include <des_key.hxx>
#include <string>

class des {
  std::bitset<64> cipher_initial_permutation(std::bitset<64>);
  std::bitset<48> cipher_expansion_permutation(std::bitset<32>, std::array<std::uint8_t, 48>);
  std::bitset<32> cipher_permutation(std::bitset<32>);
  std::bitset<4> cipher_substitution_permutation(std::bitset<6>, std::array<std::array<std::uint8_t, 16>, 4>);
  std::bitset<64> cipher_final_permutation(std::bitset<64>);
  std::bitset<64> cipher_block_gen(std::bitset<64>, std::bitset<48>);

  std::bitset<64> cipher_inverse_initial_permutation(std::bitset<64>);
  std::bitset<64> cipher_inverse_block_gen(std::bitset<64>, std::bitset<48>);
  std::bitset<64> cipher_inverse_final_permutation(std::bitset<64>);

  
public:
  des(const des_key&,
      const std::array<std::uint8_t, 64>& = des::STANDARD_IP_TABLE,
      const std::array<std::uint8_t, 48>& = des::STANDARD_E_TABLE,
      const std::array<std::array<std::array<std::uint8_t, 16>, 4>, 8>& = des::STANDARD_S_BOXES,
      const std::array<std::uint8_t, 32>& = des::STANDARD_P_TABLE,
      const std::array<std::uint8_t, 64>& = des::STANDARD_FP_TABLE);

  des(des_key&&,
      const std::array<std::uint8_t, 64>& = des::STANDARD_IP_TABLE,
      const std::array<std::uint8_t, 48>& = des::STANDARD_E_TABLE,
      const std::array<std::array<std::array<std::uint8_t, 16>, 4>, 8>& = des::STANDARD_S_BOXES,
      const std::array<std::uint8_t, 32>& = des::STANDARD_P_TABLE,
      const std::array<std::uint8_t, 64>& = des::STANDARD_FP_TABLE);

  des(des_key&&,
      std::array<std::uint8_t, 64>&&,
      std::array<std::uint8_t, 48>&&,
      std::array<std::array<std::array<std::uint8_t, 16>, 4>, 8>&&,
      std::array<std::uint8_t, 32>&&,
      std::array<std::uint8_t, 64>&&);

  std::string encrypt(std::string);
  std::string decrypt(std::string);

  const des_key des_key_gen;
  const std::array<std::uint8_t, 64> ip_table;
  const std::array<std::uint8_t, 48> e_table;
  const std::array<std::array<std::array<std::uint8_t, 16>, 4>, 8> s_boxes;
  const std::array<std::uint8_t, 32> p_table;
  const std::array<std::uint8_t, 64> fp_table;

  static std::array<std::uint8_t, 64> cipher_initial_permutation_table_gen();
  static std::array<std::uint8_t, 48> cipher_expansion_table_gen();
  static std::array<std::array<std::uint8_t, 16>, 4> cipher_substitution_box_gen();
  static std::array<std::array<std::array<std::uint8_t, 16>, 4>, 8> cipher_all_substitution_boxes_gen();
  static std::array<std::uint8_t, 32> cipher_permutation_table_gen();
  static std::array<std::uint8_t, 64> cipher_final_permutation_table_gen();
   
  constexpr const static std::array<std::uint8_t, 64> STANDARD_IP_TABLE = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
  };

  constexpr const static std::array<std::uint8_t, 48> STANDARD_E_TABLE = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
  };

  constexpr const static std::array<std::array<std::array<std::uint8_t, 16>, 4>, 8> STANDARD_S_BOXES = {
    std::array<std::array<std::uint8_t, 16>, 4>({
      std::array<std::uint8_t, 16>({14,  4, 13, 1,  2, 15,  11,  8,   3, 10,  6, 12,  5,  9, 0,  7}),
      std::array<std::uint8_t, 16>({ 0, 15,  7, 4, 14,  2,  13,  1,  10,  6, 12, 11,  9,  5, 3,  8}),
      std::array<std::uint8_t, 16>({ 4,  1, 14, 8, 13,  6,   2, 11,  15, 12,  9,  7,  3, 10, 5,  0}),
      std::array<std::uint8_t, 16>({15, 12,  8, 2,  4,  9,   1,  7,   5, 11,  3, 14, 10,  0, 6, 13}) }),
    std::array<std::array<std::uint8_t, 16>, 4>({
      std::array<std::uint8_t, 16>({15,  1,  8, 14,  6, 11,  3,  4,  9, 7,  2, 13, 12, 0,  5, 10}),
      std::array<std::uint8_t, 16>({ 3, 13,  4,  7, 15,  2,  8, 14, 12, 0,  1, 10,  6, 9, 11,  5}),
      std::array<std::uint8_t, 16>({ 0, 14,  7, 11, 10,  4, 13,  1,  5, 8, 12,  6,  9, 3,  2, 15}),
      std::array<std::uint8_t, 16>({13,  8, 10,  1,  3, 15,  4,  2, 11, 6,  7, 12,  0, 5, 14,  9}) }),
    std::array<std::array<std::uint8_t, 16>, 4>({
      std::array<std::uint8_t, 16>({10,  0,  9, 14, 6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8}),
      std::array<std::uint8_t, 16>({13,  7,  0,  9, 3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1}),
      std::array<std::uint8_t, 16>({13,  6,  4,  9, 8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7}),
      std::array<std::uint8_t, 16>({ 1, 10, 13,  0, 6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}),
    }),
    std::array<std::array<std::uint8_t, 16>, 4>({
      std::array<std::uint8_t, 16>({ 7, 13, 14, 3,  0,  6,  9, 10,  1, 2, 8,  5, 11, 12,  4, 15}),
      std::array<std::uint8_t, 16>({13,  8, 11, 5,  6, 15,  0,  3,  4, 7, 2, 12,  1, 10, 14,  9}),
      std::array<std::uint8_t, 16>({10,  6,  9, 0, 12, 11,  7, 13, 15, 1, 3, 14,  5,  2,  8,  4}),
      std::array<std::uint8_t, 16>({ 3, 15,  0, 6, 10,  1, 13,  8,  9, 4, 5, 11, 12,  7,  2, 14}),
    }),
    std::array<std::array<std::uint8_t, 16>, 4>({
      std::array<std::uint8_t, 16>({ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13, 0, 14,  9}),
      std::array<std::uint8_t, 16>({14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3, 9,  8,  6}),
      std::array<std::uint8_t, 16>({ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6, 3,  0, 14}),
      std::array<std::uint8_t, 16>({11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10, 4,  5,  3}),
    }),
    std::array<std::array<std::uint8_t, 16>, 4>({
      std::array<std::uint8_t, 16>({12,  1, 10, 15, 9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11}),
      std::array<std::uint8_t, 16>({10, 15,  4,  2, 7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8}),
      std::array<std::uint8_t, 16>({ 9, 14, 15,  5, 2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6}),
      std::array<std::uint8_t, 16>({ 4,  3,  2, 12, 9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}),
    }),
    std::array<std::array<std::uint8_t, 16>, 4>({
      std::array<std::uint8_t, 16>({ 4, 11,  2, 14, 15, 0,  8, 13,  3, 12, 9,  7,  5, 10, 6,  1}),
      std::array<std::uint8_t, 16>({13,  0, 11,  7,  4, 9,  1, 10, 14,  3, 5, 12,  2, 15, 8,  6}),
      std::array<std::uint8_t, 16>({ 1,  4, 11, 13, 12, 3,  7, 14, 10, 15, 6,  8,  0,  5, 9,  2}),
      std::array<std::uint8_t, 16>({ 6, 11, 13,  8,  1, 4, 10,  7,  9,  5, 0, 15, 14,  2, 3, 12}),
    }),
    std::array<std::array<std::uint8_t, 16>, 4>({
      std::array<std::uint8_t, 16>({13,  2,  8, 4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7}),
      std::array<std::uint8_t, 16>({ 1, 15, 13, 8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2}),
      std::array<std::uint8_t, 16>({ 7, 11,  4, 1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8}),
      std::array<std::uint8_t, 16>({ 2,  1, 14, 7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}),
    })
  };
  constexpr const static std::array<std::uint8_t, 32> STANDARD_P_TABLE = {
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
  };

  constexpr const static std::array<std::uint8_t, 64> STANDARD_FP_TABLE = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25
  };
};
