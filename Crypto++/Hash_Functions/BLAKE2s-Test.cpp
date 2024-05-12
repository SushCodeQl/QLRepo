#include "cryptlib.h"
#include "blake2.h"
#include <iostream>

int main (int argc, char* argv[])
{
    using namespace CryptoPP;
	HexEncoder encoder(new FileSink(std::cout));

	std::string msg = "Yoda said, Do or do not. There is not try.";
	std::string digest;

	BLAKE2s hash;
	hash.Update((const byte*)msg.data(), msg.size());
	digest.resize(hash.DigestSize());
	hash.Final((byte*)&digest[0]);

	std::cout << "Message: " << msg << std::endl;

	std::cout << "Digest: ";
	StringSource(digest, true, new Redirector(encoder));
	std::cout << std::endl;

    return 0; 
}