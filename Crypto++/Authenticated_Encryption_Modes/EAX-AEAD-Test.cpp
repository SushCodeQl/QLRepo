// sample.cpp

#include "stdafx.h"

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "filters.h"
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::ArraySource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::AAD_CHANNEL;
using CryptoPP::DEFAULT_CHANNEL;

#include "aes.h"
using CryptoPP::AES;

#include "eax.h"
using CryptoPP::EAX;

#include <string>
using std::string;

#include <iostream>
using std::cout;
using std::endl;

int main(int argc, char* argv[])
{
    string adata="Authenticated data", pdata="Encrypted data";

    // Encrypted, with Tag
    string ciphertext;

    // Recovered
    string radata, rpdata;

    // Book keeping
    size_t n = (size_t)-1;

    try {

        ////////////////////////////////////////////////
        // Generate keys
        AutoSeededRandomPool rng;

        byte key[ AES::DEFAULT_KEYLENGTH ];
        rng.GenerateBlock( key, sizeof(key) );

        byte iv[ AES::BLOCKSIZE * 16 ];
        rng.GenerateBlock( iv, sizeof(iv) );

        const int TAG_SIZE = 12;

        ////////////////////////////////////////////////
        // Encrpytion
        EAX< AES >::Encryption e;
        // e.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );

        AuthenticatedEncryptionFilter ef( e,
            NULL, false, TAG_SIZE
            /* MAC_AT_END */
         );  // AuthenticatedEncryptionFilter


        // AuthenticatedEncryptionFilter::ChannelPut
        //  defines two channels: DEFAULT_CHANNEL (empty) and AAD_CHANNEL
        //   DEFAULT_CHANNEL is encrypted and authenticated
        //   AAD_CHANNEL is authenticated
        ef.ChannelPut( AAD_CHANNEL, (const byte*)adata.data(), adata.size() );
        ef.ChannelMessageEnd(AAD_CHANNEL);

        // Authenticated data *must* be pushed before
        //  Confidential/Authenticated data. Otherwise
        //  we must catch the BadState exception
        ef.ChannelPut( DEFAULT_CHANNEL, (const byte*)pdata.data(), pdata.size() );
        ef.ChannelMessageEnd(DEFAULT_CHANNEL);              

        // Remove data from channel
        n = (size_t)ef.MaxRetrievable();
        ciphertext.resize( n );
        if( n > 0 ) { ef.Get( (byte*)ciphertext.data(), ciphertext.size() ); }

        ////////////////////////////////////////////////
        // Authenticated Data is sent via clear text
        radata = adata;

        ////////////////////////////////////////////////
        // Tamper
        // ciphertext[0] |= 0x0F;
        // radata[0] |= 0xF0;

        ////////////////////////////////////////////////
        // Break the cipher text out into it's
        //  components: Encrypted and MAC (MAC_AT_END)
        string enc = ciphertext.substr( 0, ciphertext.length()-TAG_SIZE );
        string tag = ciphertext.substr( ciphertext.length()-TAG_SIZE );

        // Sanity checks
        assert( ciphertext.size() == enc.size() + tag.size() );
        assert( enc.size() == pdata.size() );
        assert( TAG_SIZE == tag.size() );

        ////////////////////////////////////////////////
        // Decrpytion
        EAX< AES >::Decryption d;
        d.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );

        AuthenticatedDecryptionFilter df( d, NULL,
            AuthenticatedDecryptionFilter::DEFAULT_FLAGS, TAG_SIZE
            /* MAC_AT_END */
        ); // AuthenticatedDecryptionFilter

        // ADATA must be inserted first
        df.ChannelPut( AAD_CHANNEL, (const byte*)radata.data(), radata.size() );

        // PDATA (encrypted)
        df.ChannelPut( DEFAULT_CHANNEL, (const byte*)enc.data(), enc.size() );

        // TAG last on default channel
        df.ChannelPut( DEFAULT_CHANNEL, (const byte*)tag.data(), tag.size() );

        // Finished
        df.MessageEnd();

        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity
        bool b = df.GetLastResult();
        assert( true == b );

        // Plain text recovered from enc.data()
        n = (size_t)df.MaxRetrievable();
        rpdata.resize( n );

        if( n > 0 ) { df.Get( (byte*)rpdata.data(), n ); }

        // All is well - work with data

        assert( pdata == rpdata );
        cout << "Recovered original message" << endl;

    } // try

    catch( CryptoPP::Exception&e )
    {
        std::cerr << "Error: " << e.what() << endl;
    }

    return 0;
}
