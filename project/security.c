#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SIGNATURE_SIZE 72

#define CLIENT_HELLO_SEND 2
#define SERVER_HELLO_SEND 3
#define SERVER_CLIENT_HELLO_AWAIT 4


int cur_type = -1;
int client_hello_finished = 0;
int state = -1;

void init_sec(int type, char* host) {
    cur_type = type; 
    if (type == CLIENT){
        state = CLIENT_HELLO_SEND;
    }
    else if (type == SERVER){
        state = SERVER_CLIENT_HELLO_AWAIT;
    }
    init_io();
}

tlv* cached_client_hello = NULL;
tlv* cached_server_hello = NULL;

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    
    if (cur_type == CLIENT){
        //building a client hello tlv
        tlv* ch = create_tlv(CLIENT_HELLO);

        //creating a nonce tlv object 
        tlv* nn = create_tlv(NONCE);
        uint8_t nonce[NONCE_SIZE];
        generate_nonce(nonce, NONCE_SIZE); 
        add_val(nn, nonce, NONCE_SIZE);
        add_tlv(ch, nn);

        //derive public/private key pair 
        generate_private_key();
        derive_public_key();
        tlv* pubkey = create_tlv(PUBLIC_KEY);
        add_val(pubkey, public_key, pub_key_size);
        add_tlv(ch, pubkey);

        uint16_t len = serialize_tlv(buf, ch);
        cached_client_hello  = ch;
        print("MY CLIENT HELLO");
        print_tlv_bytes(buf, len);
        //free_tlv(ch);
        return len;

    }

    //if currently server and client hello finished
    if (cur_type == SERVER){
       
       
        uint16_t offset = 0;

        //building a server hello tlv 0x20
        tlv* sh = create_tlv(SERVER_HELLO);

        //creating a nonce tlv object 
        tlv* nn_s = create_tlv(NONCE);
        uint8_t nonce_s[NONCE_SIZE];
        generate_nonce(nonce_s, NONCE_SIZE); 
        add_val(nn_s, nonce_s, NONCE_SIZE);
        add_tlv(sh, nn_s);
        
       
        //server cert bin 
        //first we load the certificate of the server_cert.bin, which stores values in the certificate global variable
        load_certificate("server_cert.bin");
        tlv* cert_tlv = deserialize_tlv(certificate, cert_size);
        // tlv* cert_tlv = create_tlv(CERTIFICATE);
        // add_val(cert_tlv, certificate, cert_size);
        add_tlv(sh, cert_tlv);

        //now we generate an "Ephemeral" public key 
        generate_private_key();
        derive_public_key();
        tlv* pubkey_s = create_tlv(PUBLIC_KEY);
        add_val(pubkey_s, public_key, pub_key_size);
        add_tlv(sh, pubkey_s);

        // then we build a tlv for handshake
        tlv* handshake = create_tlv(HANDSHAKE_SIGNATURE);
        EVP_PKEY* ephemeral_priv = get_private_key();
        load_private_key("server_key.bin");

        //creating a handshake buffer
        uint8_t handshake_buffer[max_length];

        offset += serialize_tlv(handshake_buffer + offset , cached_client_hello);
        offset += serialize_tlv(handshake_buffer + offset, nn_s);
        // memcpy(handshake_buffer + offset, certificate, cert_size);
        // offset += cert_size;
        offset += serialize_tlv(handshake_buffer + offset, cert_tlv);
        offset += serialize_tlv(handshake_buffer + offset, pubkey_s);

        uint8_t signature[256];

        // signature generated 
        size_t signature_size = sign(signature, handshake_buffer, offset);
        add_val(handshake, signature, signature_size);
        set_private_key(ephemeral_priv);
        add_tlv(sh, handshake);

        uint16_t len = serialize_tlv(buf, sh);
        cached_server_hello = sh;

        print_tlv_bytes(buf, len);
        
        free_tlv(sh);
        //free(salt);
        //finish server hello
        return len;

    }

    return input_io(buf, max_length);
    
}

void output_sec(uint8_t* buf, size_t length) {
    output_io(buf, length);

    if (cur_type == SERVER){
        // Deserialize the Client Hello from the received buffer
        tlv* ch = deserialize_tlv(buf, length);
        
        // Cache the deserialized Client Hello for later use
        cached_client_hello = ch;
        //state == SERVER_HELLO_SEND;
    }
    
}
