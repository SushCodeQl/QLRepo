AutoSeededRandomPool prng;

SecByteBlock key(RC6::DEFAULT_KEYLENGTH);
prng.GenerateBlock(key, key.size());

byte iv[RC6::BLOCKSIZE];
prng.GenerateBlock(iv, sizeof(iv));

string plain = "CBC Mode Test";
string cipher, encoded, recovered;

/*********************************\
\*********************************/

try
{
    cout << "plain text: " << plain << endl;

    CBC_Mode< RC6 >::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);

    // The StreamTransformationFilter adds padding
    //  as required. ECB and CBC Mode must be padded
    //  to the block size of the cipher.
    StringSource(plain, true, 
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

// Pretty print
StringSource(cipher, true,
    new HexEncoder(
        new StringSink(encoded)
    ) // HexEncoder
); // StringSource

cout << "cipher text: " << encoded << endl;

/*********************************\
\*********************************/

try
{
    CBC_Mode< RC6 >::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);

    // The StreamTransformationFilter removes
    //  padding as required.
    StringSource s(cipher, true, 
        new StreamTransformationFilter(d,
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