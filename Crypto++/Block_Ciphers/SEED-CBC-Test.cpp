using namespace CryptoPP;

void Print(const std::string& label, const std::string& val)
{
   std::string encoded;
   StringSource(val, true,
      new HexEncoder(
         new StringSink(encoded)
      ) // HexEncoder
   ); // StringSource

   std::cout << label << ": " << encoded << std::endl;
}

int main(int argc, char* argv[])
{
   AutoSeededRandomPool prng;
   SecByteBlock key(SEED::DEFAULT_KEYLENGTH);
   SecByteBlock iv(SEED::BLOCKSIZE);

   prng.GenerateBlock(key, key.size());
   prng.GenerateBlock(iv, iv.size());

   std::string plain = "CBC Mode Test";
   std::string cipher, encoded, recovered;

   /*********************************\
   \*********************************/

   try
   {
      std::cout << "plain text: " << plain << std::endl;

      CBC_Mode< SEED >::Encryption e;
      e.SetKeyWithIV(key, key.size(), iv);

      // The StreamTransformationFilter adds padding
      //  as required. ECB and CBC Mode must be padded
      //  to the block size of the cipher.
      StringSource s(plain, true, 
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

   Print("key", std::string((const char*)key.begin(), key.size()));
   Print("iv", std::string((const char*)iv.begin(), iv.size()));
   Print("cipher text", cipher);

   /*********************************\
   \*********************************/

   try
   {
      CBC_Mode< SEED >::Decryption d;
      d.SetKeyWithIV(key, key.size(), iv);

      // The StreamTransformationFilter removes
      //  padding as required.
      StringSource s(cipher, true, 
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
   return 0;
}