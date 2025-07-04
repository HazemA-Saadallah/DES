#include <iomanip>
#include <sstream>
#include <cstdlib>
#include <iostream>
#include <des_key.hxx>
#include <des.hxx>

std::string stringToHex(const std::string& str) {
  std::ostringstream oss;
  for (unsigned char c : str) oss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(c);
  return oss.str();
}

int main (void) {
  std::cin.tie(nullptr);
  std::cout.tie(nullptr);
  std::ios::sync_with_stdio(false);

  std::string plain_text = "ThIs Is A vErY sEcReT ... 123456789";
  des_key des_key_obj(0x133457799BBCDFF1);
  des des_obj(std::move(des_key_obj));

  std::string cipher_text = des_obj.encrypt(plain_text);
  std::string plain_text_r = des_obj.decrypt(cipher_text);
  std::cout <<"Plain text:   " <<plain_text <<"\t(0x" <<stringToHex(plain_text) <<")\n"
            <<"Cipher text:  " <<cipher_text <<"\t\t(0x" <<stringToHex(cipher_text) <<")\n" 
            <<"Plain text R: " <<plain_text_r <<"\t(0x" <<stringToHex(plain_text_r) <<")\n"
            <<"\noriginal len: " <<plain_text.length()
            <<"\nnew len: " <<plain_text_r.length()
            <<std::endl;

  return EXIT_SUCCESS;
}
