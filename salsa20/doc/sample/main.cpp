#include <string>
#include "Salsa20Helper.h"

int main()
{
    BYTE key[Salsa20::KEY_SIZE+1] = "01234567890123456789012367890123";
    BYTE iv[Salsa20::IV_SIZE+1] = "45678901";

    Salsa20Helper salsa_file(key, iv);
    salsa_file.Transfer("in.dat", "out.dat");
    
    std::string value = "0123456789abcdefghijklmnopqrstuvwxyz";
    BYTE *out = new BYTE(value.size);
    Salsa20Helper salsa(key, iv);
    salsa.Transfer(reinterpret_cast<const uint8_t *>(value.data()), reinterpret_cast<uint8_t *>(out), value.size());
    std::ofstream outputStream("out.dat", std::ios_base::binary);
    outputStream.write(reinterpret_cast<const char *>(out), value.size());
    exit(0);
}
