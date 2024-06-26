int main(int argc, char* argv[])
{
    byte key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
    byte iv[] = "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";

    CBC_Mode<Kalyna>::Encryption kalyna;
    kalyna.SetKeyWithIV(key, 16, iv, 16);
    
    byte plain[] = "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F"
        "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F"
        "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F";        

    BlockPaddingSchemeDef::BlockPaddingScheme padding = BlockPaddingSchemeDef::NO_PADDING;
    StreamTransformationFilter encryptor(kalyna, new HexEncoder(new FileSink(cout)), padding);
    
    cout << "Cipher text: ";
    encryptor.Put(plain, 48);
    encryptor.MessageEnd();
    cout << endl;
    
    return 0;
}