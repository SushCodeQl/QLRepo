#include "cryptlib.h"
#include "secblock.h"
#include "filters.h"
#include "hc128.h"
#include "osrng.h"
#include "files.h"
#include "hex.h"

#include <iostream>
#include <string>

int main()
{
    using namespace CryptoPP;

    AutoSeededRandomPool prng;
    HexEncoder encoder(new FileSink(std::cout));
    std::string plain("HC-128 stream cipher test"), cipher, recover;

    SecByteBlock key(16), iv(16);
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    std::cout << "Key: ";
    encoder.Put(key.data(), key.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    std::cout << "IV: ";
    encoder.Put(iv.data(), iv.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    // Encryption object
    HC128::Encryption enc;    
    enc.SetKeyWithIV(key, key.size(), iv, iv.size());

    // Decryption object
    HC128::Decryption dec;    
    dec.SetKeyWithIV(key, key.size(), iv, iv.size());

    StringSource ss1(plain, true, new StreamTransformationFilter(enc, new StringSink(cipher)));
    StringSource ss2(cipher, true, new StreamTransformationFilter(dec, new StringSink(recover)));

    std::cout << "Plain: " << plain << std::endl;

    std::cout << "Cipher: ";
    encoder.Put((const byte*)cipher.data(), cipher.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    std::cout << "Recovered: " << recover << std::endl;

    return 0;
}