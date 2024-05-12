// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "serpent.h"
using CryptoPP::Serpent;

#include "eax.h"
using CryptoPP::EAX;

#include "secblock.h"
using CryptoPP::SecByteBlock;

int main(int argc, char* argv[])
{
	AutoSeededRandomPool prng;

	SecByteBlock key(Serpent::DEFAULT_KEYLENGTH);
	prng.GenerateBlock(key, key.size());

	byte iv[Serpent::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	// cout << "key length: " << Serpent::DEFAULT_KEYLENGTH << endl;
	// cout << "key length (min): " << Serpent::MIN_KEYLENGTH << endl;
	// cout << "key length (max): " << Serpent::MAX_KEYLENGTH << endl;
	// cout << "block size: " << Serpent::BLOCKSIZE << endl;

	string plain = "EAX Mode Test";
	string cipher, encoded, recovered;

	/*********************************\
	\*********************************/

	// Pretty print key
	encoded.clear();
	StringSource ss1(key, key.size(), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "key: " << encoded << endl;

	// Pretty print iv
	encoded.clear();
	StringSource ss2(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "iv: " << encoded << endl;

	/*********************************\
	\*********************************/

	try
	{
		cout << "plain text: " << plain << endl;

		EAX< Serpent >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		StringSource ss3(plain, true, 
			new AuthenticatedEncryptionFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// Tamper
	// cipher[0] ^= 0x01;

	/*********************************\
	\*********************************/

	// Pretty print
	encoded.clear();
	StringSource ss4(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "cipher text: " << encoded << endl;

	/*********************************\
	\*********************************/

	try
	{
		EAX< Serpent >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		StringSource ss5(cipher, true, 
			new AuthenticatedDecryptionFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

		cout << "recovered text: " << recovered << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	return 0;
}

