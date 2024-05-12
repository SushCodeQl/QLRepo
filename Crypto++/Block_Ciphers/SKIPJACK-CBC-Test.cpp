AutoSeededRandomPool prng;

SecByteBlock key(SKIPJACK::DEFAULT_KEYLENGTH);
prng.GenerateBlock(key, key.size());

SecByteBlock iv(SKIPJACK::BLOCKSIZE);
prng.GenerateBlock(iv, iv.size());

std::string plain = "CBC Mode Test";
std::string cipher, encoded, recovered;

/*********************************\
\*********************************/

try
{
    std::cout << "plain text: " << plain << std::endl;

    CBC_Mode< SKIPJACK >::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);

    // The StreamTransformationFilter adds padding
    //  as required. ECB and CBC Mode must be padded
    //  to the block size of the cipher.
    StringSource ss1(plain, true,
        new StreamTransformationFilter(e,
            new StringSink(cipher)
        ) // StreamTransformationFilter
    ); // StringSource
}
catch(const CryptoPP::Exception& e)
{
    std::cerr << e.what() << std::endl;
    exit(1);
}

/*********************************\
\*********************************/

// Pretty print

encoded.clear();
StringSource ss2(key.begin(), key.size(), true,
    new HexEncoder(
        new StringSink(encoded)
    ) // HexEncoder
); // StringSource
std::cout << "key: " << encoded << std::endl;

encoded.clear();
StringSource ss3(iv.begin(), iv.size(), true,
    new HexEncoder(
        new StringSink(encoded)
    ) // HexEncoder
); // StringSource
std::cout << "iv: " << encoded << std::endl;

encoded.clear();
StringSource ss4(cipher, true,
    new HexEncoder(
        new StringSink(encoded)
    ) // HexEncoder
); // StringSource
std::cout << "cipher text: " << encoded << std::endl;

/*********************************\
\*********************************/

try
{
    CBC_Mode< SKIPJACK >::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);

    // The StreamTransformationFilter removes
    //  padding as required.
    StringSource ss5(cipher, true,
        new StreamTransformationFilter(d,
            new StringSink(recovered)
        ) // StreamTransformationFilter
    ); // StringSource

    std::cout << "recovered text: " << recovered << std::endl;
}
catch(const CryptoPP::Exception& e)
{
    std::cerr << e.what() << std::endl;
    exit(1);
}