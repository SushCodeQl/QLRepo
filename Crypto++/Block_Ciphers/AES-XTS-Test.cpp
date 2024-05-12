#include "cryptlib.h"
#include "filters.h"
#include "osrng.h"
#include "files.h"
#include "hex.h"
#include "aes.h"
#include "xts.h"

#include <iostream>
#include <string>

int main(int argc, char* argv[])
{
    using namespace CryptoPP;

    AutoSeededRandomPool prng;

    SecByteBlock key(32), iv(16);
    prng.GenerateBlock( key, key.size() );
    prng.GenerateBlock( iv, iv.size() );

    std::string plain = "XTS mode test";
    std::string cipher, encoded, recovered;

    /*********************************\
    \*********************************/

    try
    {
        XTS_Mode< AES >::Encryption enc;
        enc.SetKeyWithIV( key, key.size(), iv );

#if 0
        std::cout << "key length: " << enc.DefaultKeyLength() << std::endl;
        std::cout << "key length (min): " << enc.MinKeyLength() << std::endl;
        std::cout << "key length (max): " << enc.MaxKeyLength() << std::endl;
        std::cout << "block size: " << enc.BlockSize() << std::endl;
#endif

        // The StreamTransformationFilter adds padding
        //  as requiredec. ECB and XTS Mode must be padded
        //  to the block size of the cipher.
        StringSource ss( plain, true, 
            new StreamTransformationFilter( enc,
                new StringSink( cipher ),
                StreamTransformationFilter::NO_PADDING
            ) // StreamTransformationFilter      
        ); // StringSource
        std::cout << "plain text: " << plain << std::endl;
    }
    catch( const CryptoPP::Exception& ex )
    {
        std::cerr << ex.what() << std::endl;
        exit(1);
    }

    /*********************************\
    \*********************************/

    encoded.clear();
    StringSource ss1( key, key.size(), true,
        new HexEncoder(
            new StringSink( encoded )
        ) // HexEncoder
    ); // StringSource
    std::cout << "key: " << encoded << std::endl;

    encoded.clear();
    StringSource ss2( iv, iv.size(), true,
        new HexEncoder(
            new StringSink( encoded )
        ) // HexEncoder
    ); // StringSource
    std::cout << " iv: " << encoded << std::endl;

    // Pretty print cipher text
    encoded.clear();
    StringSource ss3( cipher, true,
        new HexEncoder(
            new StringSink( encoded )
        ) // HexEncoder
    ); // StringSource
    std::cout << "cipher text: " << encoded << std::endl;

    /*********************************\
    \*********************************/

    try
    {
        XTS_Mode< AES >::Decryption dec;
        dec.SetKeyWithIV( key, key.size(), iv );

        // The StreamTransformationFilter removes
        //  padding as requiredec.
        StringSource ss( cipher, true, 
            new StreamTransformationFilter( dec,
                new StringSink( recovered ),
                StreamTransformationFilter::NO_PADDING
            ) // StreamTransformationFilter
        ); // StringSource        
        std::cout << "recovered text: " << recovered << std::endl;
    }
    catch( const CryptoPP::Exception& ex )
    {
        std::cerr << ex.what() << std::endl;
        exit(1);
    }
    return 0;
}
