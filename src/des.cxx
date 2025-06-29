#include <array>
#include <bitset>
#include <des_key.hxx>
#include <des.hxx>
#include <ranges>
#include <algorithm>
#include <random>
#include <numeric>
#include <stdexcept>

des::des(des_key des_key_obj,
         std::array<std::uint8_t, 64> _ip_table,
         std::array<uint8_t, 48> _e_table,
         std::array<std::array<std::array<std::uint8_t, 16>, 4>, 8> _s_box_arr,
         std::array<uint8_t, 32> _p_table,
         std::array<uint8_t, 64> _fp_table
         ): des_key_gen(des_key_obj),
            ip_table(_ip_table),
            e_table(_e_table),
            s_boxes(_s_box_arr),
            p_table(_p_table),
            fp_table(_fp_table) {}

std::array<uint8_t, 64> des::cipher_initial_permutation_table_gen() {
  std::array<std::uint8_t, 64> result;
  std::random_device rd;
  std::mt19937 gen(rd());
  std::iota(result.begin(), result.end(), 0);
  std::shuffle(result.begin(), result.end(), gen);
  return result;
}

std::array<uint8_t, 48> des::cipher_expansion_table_gen() {
  std::array<uint8_t, 48> result;
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint16_t> dist(1, 32);
  for (uint8_t i{0}; i < 48; ++i) result[i] = static_cast<std::uint8_t>(dist(gen));
  return result;
}

std::array<std::array<std::uint8_t, 16>, 4> des::cipher_substitution_box_gen() {
  std::array<std::array<std::uint8_t, 16>, 4> result;
  std::ranges::copy(
    std::views::iota(0uz, 4uz) | std::views::transform([](std::uint8_t) { 
      std::array<uint8_t, 16> s;
      std::random_device rd;
      std::mt19937 gen(rd());
      std::iota(s.begin(), s.end(), 0);
      std::shuffle(s.begin(), s.end(), gen);
      return s; 
    }),
    result.begin());
  return result;
}

std::array<std::array<std::array<std::uint8_t, 16>, 4>, 8> des::cipher_all_substitution_boxes_gen() {
  return [] {
    std::array<std::array<std::array<uint8_t, 16>, 4>, 8> s;
    std::ranges::copy(
      std::views::iota(0uz, 8uz) | std::views::transform([](std::uint8_t) { 
          return des::cipher_substitution_box_gen(); 
      }), s.begin());
    return s;
  } ();
}

std::array<std::uint8_t, 32> des::cipher_permutation_table_gen() {
  std::array<std::uint8_t, 32> result;
  std::random_device rd;
  std::mt19937 gen(rd());
  std::iota(result.begin(), result.end(), 0);
  std::shuffle(result.begin(), result.end(), gen);
  return result;
}

std::array<std::uint8_t, 64> des::cipher_final_permutation_table_gen() {
  std::array<std::uint8_t, 64> result;
  std::random_device rd;
  std::mt19937 gen(rd());
  std::iota(result.begin(), result.end(), 0);
  std::shuffle(result.begin(), result.end(), gen);
  return result;
}

std::bitset<64> des::cipher_initial_permutation(std::bitset<64> block) {
  std::bitset<64> result;
  for (uint8_t i{0}; i < 64; ++i) result[63-i] = block[64-this->des::ip_table[i]];
  return result;
}

std::bitset<48> des::cipher_expansion_permutation(std::bitset<32> text, std::array<std::uint8_t, 48> e_table) {
  std::bitset<48> result;
  for (uint8_t i{0}; i < 48; ++i) result[47-i] = text[32-e_table[i]];
  return result;
}

std::bitset<32> des::cipher_permutation(std::bitset<32> block) {
  std::bitset<32> result;
  for (uint8_t i{0}; i < 32; ++i) result[31-i] = block[32-p_table[i]];
  return result;
}

std::bitset<4> des::cipher_substitution_permutation(std::bitset<6> chunk, std::array<std::array<std::uint8_t, 16>, 4>s_box) {
    return std::bitset<4>(s_box[(chunk[5] << 1) | chunk[0]][((chunk >> 1).to_ulong() & 0xF)]);
}

std::bitset<64> des::cipher_block_gen(std::bitset<64> block, std::bitset<48> key) {
  std::bitset<32> l0 {std::bitset<32>((block >> 32).to_ulong())}, r0 {std::bitset<32>(block.to_ulong() & 0xFFFFFFFF)}, l = r0;

  std::bitset<48> e_r_block = this->des::cipher_expansion_permutation(r0, this->des::e_table);
  std::bitset<48> e_r_block_key = e_r_block ^ key;

  std::ranges::transform_view zipped = std::views::iota(0, 8) | std::views::transform([&](int i) {
    auto chunk = std::bitset<6>((e_r_block_key >> (42 - i * 6)).to_ulong() & 0x3F);
    return this->des::cipher_substitution_permutation(chunk, this->des::s_boxes[i]);
  });

  std::uint8_t offset{0};
  std::bitset<32> e_r_block_key_s_box = std::ranges::fold_left(zipped, std::bitset<32>{}, [&](std::bitset<32> acc, const std::bitset<4>& bits) {
    for (int j = 0; j < 4; ++j) acc[31 - (offset * 4 + j)] = bits[3 - j];
    ++offset;
    return acc;
  });

  std::bitset<32> e_r_block_key_s_box_p = this->des::cipher_permutation(e_r_block_key_s_box);
  std::bitset<32> r = e_r_block_key_s_box_p ^ l0;
  return std::bitset<64>((static_cast<std::uint64_t>(l.to_ulong()) << 32) | static_cast<std::uint64_t>(r.to_ulong()));
}

std::bitset<64> des::cipher_final_permutation(std::bitset<64> block) {
  std::bitset<64> result;
  for (uint8_t i{0}; i < 64; ++i) result[63-i] = block[64-this->des::fp_table[i]];
  return result;
}

std::string des::encrypt(std::string plain_text) {
  std::string result;

  for (std::size_t i{0}; i < plain_text.length(); i += 8) {
    std::string chunk_str = plain_text.substr(i, 8);
    if (chunk_str.length() < 8) chunk_str.append(8 - chunk_str.length(), 0x00);

    std::bitset<64> chunk_bits{0};
    for (std::uint8_t i{0}; i < 8; ++i) {
      chunk_bits <<= 8;
      chunk_bits |= static_cast<std::uint8_t>(chunk_str[i]);
    }

    std::bitset<64> ip_chunk = this->des::cipher_initial_permutation(chunk_bits);
    std::bitset<64> rounds_chunk = ip_chunk;
    for (std::uint8_t j{0}; j < 16; ++j) rounds_chunk = this->des::cipher_block_gen(rounds_chunk, this->des::des_key_gen.key_list[j]);

    std::bitset<32> l16 {std::bitset<32>((rounds_chunk >> 32).to_ulong())}, r16 {std::bitset<32>(rounds_chunk.to_ulong() & 0xFFFFFFFF)};
    std::bitset<64> s_box_chunk_rev = std::bitset<64>((static_cast<std::uint64_t>(r16.to_ulong()) << 32) | static_cast<std::uint64_t>(l16.to_ulong()));
    std::bitset<64> fp_block = this->des::cipher_final_permutation(s_box_chunk_rev);

    std::ranges::transform_view bytes = std::views::iota(0, 8) | std::views::transform([&](int i) {
      std::bitset<8> byte;
      for (int j = 0; j < 8; ++j) byte[7 - j] = fp_block[63 - (i*8 + j)];
      return static_cast<char>(byte.to_ulong());
    });

    result += std::string(bytes.begin(), bytes.end());
  }
  return result;
}

std::bitset<64> des::cipher_inverse_initial_permutation(std::bitset<64> block) {
  std::bitset<64> result;
  for (uint8_t i{0}; i < 64; ++i) result[64-this->des::ip_table[i]] = block[63-i];
  return result;
}

std::bitset<64> des::cipher_inverse_final_permutation(std::bitset<64> block) {
  std::bitset<64> result;
  for (uint8_t i{0}; i < 64; ++i) result[64-this->des::fp_table[i]] = block[63-i];
  return result;
}

std::bitset<64> des::cipher_inverse_block_gen(std::bitset<64> block, std::bitset<48> key) {
  std::bitset<32> lp {std::bitset<32>((block >> 32).to_ulong())}, rp {std::bitset<32>(block.to_ulong() & 0xFFFFFFFF)}, r = lp;

  std::bitset<48> r_block_e = this->des::cipher_expansion_permutation(r, this->des::e_table);
  std::bitset<48> r_block_e_key = r_block_e ^ key;

  std::ranges::transform_view zipped = std::views::iota(0, 8) | std::views::transform([&](int i) {
    auto chunk = std::bitset<6>((r_block_e_key >> (42 - i * 6)).to_ulong() & 0x3F);
    return this->des::cipher_substitution_permutation(chunk, this->des::s_boxes[i]);
  });

  std::uint8_t offset{0};
  std::bitset<32> e_r_block_key_s_box = std::ranges::fold_left(zipped, std::bitset<32>{}, [&](std::bitset<32> acc, const std::bitset<4>& bits) {
    for (int j = 0; j < 4; ++j) acc[31 - (offset * 4 + j)] = bits[3 - j];
    ++offset;
    return acc;
  });

  std::bitset<32> r_block_e_key_s_box_p = this->des::cipher_permutation(e_r_block_key_s_box);
  std::bitset<32> l = r_block_e_key_s_box_p ^ rp;

  return std::bitset<64>((static_cast<std::uint64_t>(l.to_ulong()) << 32) | static_cast<std::uint64_t>(r.to_ulong()));
}

std::string des::decrypt(std::string cipher_text) {
  std::string result;

  for (std::size_t i{0}; i < cipher_text.length(); i += 8) {
    std::string chunk_str = cipher_text.substr(i, 8);
    if (chunk_str.length() < 8) [[unlikely]] throw std::invalid_argument("[ERROR] Invalid cipher text");

    std::bitset<64> chunk_bits{0};
    for (std::uint8_t i{0}; i < 8; ++i) {
      chunk_bits <<= 8;
      chunk_bits |= static_cast<std::uint8_t>(chunk_str[i]);
    }

    std::bitset<64> s_box_chunk_rev = this->des::cipher_inverse_final_permutation(chunk_bits);
    std::bitset<32> lp {std::bitset<32>(s_box_chunk_rev.to_ulong() & 0xFFFFFFFF)}, rp {std::bitset<32>((s_box_chunk_rev >> 32).to_ulong())};
    std::bitset<64> rounds_chunk_p = std::bitset<64>((static_cast<std::uint64_t>(lp.to_ulong()) << 32) | static_cast<std::uint64_t>(rp.to_ulong()));

    for (std::uint8_t j{0}; j < 16; ++j) rounds_chunk_p = this->des::cipher_inverse_block_gen(rounds_chunk_p, this->des_key_gen.key_list[15-j]);
    std::bitset<64> plain_text_chunk = this->des::cipher_inverse_initial_permutation(rounds_chunk_p);

    std::ranges::transform_view bytes = std::views::iota(0, 8) | std::views::transform([&](int i) {
      std::bitset<8> byte;
      for (int j = 0; j < 8; ++j) byte[7 - j] = plain_text_chunk[63 - (i*8 + j)];
      return static_cast<char>(byte.to_ulong());
    });
    result += std::string(bytes.begin(), bytes.end());
  }
  while (result.ends_with((char)0x00)) result = result.substr(0, result.length()-1);
  return result;
}
