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
using CryptoPP::StreamTransformationFilter;

#include "files.h"
using CryptoPP::FileSink;

#include "twofish.h"
using CryptoPP::Twofish;

#include "modes.h"
using CryptoPP::ECB_Mode;

#include "secblock.h"
using CryptoPP::SecByteBlock;

#ifdef CRYPTOPP_NO_GLOBAL_BYTE
using CryptoPP::byte;
#endif

int main(int argc, char* argv[])
{
	AutoSeededRandomPool prng;
	HexEncoder encoder(new FileSink(cout));

	SecByteBlock key(Twofish::DEFAULT_KEYLENGTH);
	prng.GenerateBlock(key, key.size());

	// cout << "key length: " << Twofish::DEFAULT_KEYLENGTH << endl;
	// cout << "key length (min): " << Twofish::MIN_KEYLENGTH << endl;
	// cout << "key length (max): " << Twofish::MAX_KEYLENGTH << endl;
	// cout << "block size: " << Twofish::BLOCKSIZE << endl;

	string plain = "ECB Mode Test";
	string cipher, recovered;

	/*********************************\
	\*********************************/

	// Pretty print key
	cout << "key: ";
	encoder.Put(key, key.size());
	encoder.MessageEnd();
	cout << endl;

	cout << "plain text: " << plain << endl;

	/*********************************\
	\*********************************/

	try
	{

		ECB_Mode< Twofish >::Encryption e;
		e.SetKey(key, key.size());

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher. CTR does not.
		StringSource ss(plain, true, 
			new StreamTransformationFilter(e,
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

	try
	{
		ECB_Mode< Twofish >::Decryption d;
		d.SetKey(key, key.size());

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource ss(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
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

	// Pretty print cipher text
	cout << "cipher text: ";
	encoder.Put((const byte*)&cipher[0], cipher.size());
	encoder.MessageEnd();
	cout << endl;

	cout << "recovered text: " << recovered << endl;

	return 0;
}

