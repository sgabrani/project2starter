#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


// Max size for an ECDSA signature (ASN.1 format)
#define SIGNATURE_SIZE 72

#define CLIENT_HELLO_SEND 2
#define SERVER_HELLO_SEND 3
#define SERVER_CLIENT_HELLO_AWAIT 4
#define CLIENT_SERVER_HELLO_AWAIT 5
#define CLIENT_SEND_FINISHED 6
#define SERVER_HELLO_FINISHED 7


int cur_type = -1;
int client_hello_finished = 0;
char* cur_host = "";
int client_state = -1;
int server_state = -1;

void init_sec(int type, char* host) {
    cur_type = type; 
    cur_host = host;
    if (type == CLIENT){
        client_state = CLIENT_HELLO_SEND;
    }
    else if (type == SERVER){
        server_state = SERVER_CLIENT_HELLO_AWAIT;
    }
    init_io();
}

tlv* cached_client_hello = NULL;
tlv* cached_server_hello = NULL;
tlv* finished_message = NULL;

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    
    if (cur_type == CLIENT && client_state ==  CLIENT_HELLO_SEND){
        //building a client hello tlv
        tlv* ch = create_tlv(CLIENT_HELLO);

        //creating a nonce tlv object 
        tlv* nn = create_tlv(NONCE);

        //declaring an empty 32 byte nonce array, since Nonce Size is 32
        uint8_t nonce[NONCE_SIZE];

        // Generate random nonce from provided libsecurity.h function
        generate_nonce(nonce, NONCE_SIZE); 

        //add nonce and nonce size to tlv object
        add_val(nn, nonce, NONCE_SIZE);

        //add nonce tlv object to client hello tlv
        add_tlv(ch, nn);

        //derive public/private key pair 
        //Randomly generate a private key (can be retrieved using get_private_key). Make sure to call this (or load_private_key/set_private_key) before any operations that require a private key (such as derive_public_key, derive_secret, derive_keys, sign, encrypt_data, decrypt_cipher, and hmac).
        generate_private_key();
        //From the loaded private key, generates the public key in ASN.1 format and places it in the public_key global variable.
        derive_public_key();

        //generating public key TLV
        tlv* pubkey = create_tlv(PUBLIC_KEY);

        //add public key and key size to pubkey tlv
        add_val(pubkey, public_key, pub_key_size);

        //add public key tlv object to client hello lv
        add_tlv(ch, pubkey);

        uint16_t len = serialize_tlv(buf, ch);

        //create a global client hello tlv
        cached_client_hello  = ch;


        //state = CLIENT_SERVER_HELLO_AWAIT;
        //free_tlv(ch);
        client_state = CLIENT_SERVER_HELLO_AWAIT;
        return len;
        
    }

    //if currently server and client hello finished
    if (cur_type == SERVER && server_state == SERVER_HELLO_SEND){
       
        uint16_t offset = 0;

        //building a server hello tlv 0x20
        tlv* sh = create_tlv(SERVER_HELLO);

        //creating a nonce tlv object 
        tlv* nn_s = create_tlv(NONCE);

        //declaring an empty 32 byte nonce array, since Nonce Size is 32
        uint8_t nonce_s[NONCE_SIZE];

        // Generate random nonce from provided libsecurity.h function
        generate_nonce(nonce_s, NONCE_SIZE); 

        //add nonce and nonce size to tlv object
        add_val(nn_s, nonce_s, NONCE_SIZE);
        
        //add nonce tlv to server tlv
        add_tlv(sh, nn_s);
        
       
        //server cert bin 
        //first we load the certificate of the server_cert.bin, which stores values in the certificate global variable
        load_certificate("server_cert.bin");

        // Append the certificate buffer directly to the Server Hello
        // then we build a tlv for the certificate
        tlv* cert_tlv = create_tlv(CERTIFICATE);
        
        //add_val(sh, certificate, cert_size);
        add_val(cert_tlv, certificate, cert_size);

        // add cert tlv to sh
        add_tlv(sh, cert_tlv);

        //now we generate an "Ephemeral" public key 
        generate_private_key();
        derive_public_key();

        //generating public key TLV
        tlv* pubkey_s = create_tlv(PUBLIC_KEY);

        //add public key and key size to pubkey tlv
        add_val(pubkey_s, public_key, pub_key_size);
        
        //add public key tlv object to server hello tlv
        add_tlv(sh, pubkey_s);

        // then we build a tlv for the handshake
        tlv* handshake = create_tlv(HANDSHAKE_SIGNATURE);

        EVP_PKEY* ephemeral_priv = get_private_key();

        // loading the private key before the sign function
        load_private_key("server_key.bin");

        //creating a handshake buffer
        uint8_t handshake_buffer[max_length];

        offset += serialize_tlv(handshake_buffer + offset , cached_client_hello);
        offset += serialize_tlv(handshake_buffer + offset, nn_s);
        offset += serialize_tlv(handshake_buffer + offset, cert_tlv);
        offset += serialize_tlv(handshake_buffer + offset, pubkey_s);

        uint8_t signature[72] = {0};

        // signature generated 
        size_t signature_size = sign(signature, handshake_buffer, offset);

        add_val(handshake, signature, signature_size);

        print_tlv_bytes(handshake_buffer, max_length);

        set_private_key(ephemeral_priv);

        // add handshake signature tlv object to server hello tlv
        add_tlv(sh, handshake);

        

        uint16_t len = serialize_tlv(buf, sh);
        cached_server_hello = sh;

        // Generate the salt (Client-Hello || Server-Hello)
        uint8_t salt[cached_client_hello->length + cached_server_hello->length+6]; // Allocate enough space
        uint16_t salt_size = 0;
        

        // Append cached_client_hello and cached_server_hello to salt buffer 
        salt_size += serialize_tlv(salt + salt_size, cached_client_hello);
        salt_size += serialize_tlv(salt + salt_size, cached_server_hello);

        //then derive the ENC key and a MAC key
        derive_keys(salt, salt_size);

        print_tlv_bytes(buf, max_length);
        
        //free_tlv(sh);
        //free(salt)
       
        server_state = SERVER_HELLO_FINISHED;
        //finish server hello
        return len;
    }

    if (cur_type == CLIENT && client_state == CLIENT_SEND_FINISHED){
       fprintf(stderr, "SENDING HERE");
       uint16_t len = serialize_tlv(buf, finished_message);
       print_tlv_bytes(buf, max_length);
       return len;
    }

    return 0;
    
}



void output_sec(uint8_t* buf, size_t length) {
    
    fprintf(stderr, "DEBUG: cur_type=%d, client_state=%d\n", cur_type, client_state);
    fprintf(stderr, "DEBUG: cur_type=%d, server_state=%d\n", cur_type, server_state);

    if (cur_type == SERVER && server_state == SERVER_CLIENT_HELLO_AWAIT){
        // Deserialize the Client Hello from the received buffer
        tlv* ch = deserialize_tlv(buf, length);
        
        // Cache the deserialized Client Hello for later use
        cached_client_hello = ch;
        server_state = SERVER_HELLO_SEND;
    }

    if(cur_type == CLIENT && client_state == CLIENT_SERVER_HELLO_AWAIT){

        fprintf(stderr, "GOIGN THROUGH\n");

        //compare key in certificate with the CA's public key 
        //access public key

        // if (cached_server_hello != NULL) {
        //     free_tlv(cached_server_hello); // Ensure this function properly frees the TLV structure
        //     cached_server_hello = NULL;
        // }
        
        tlv* sh = deserialize_tlv(buf,length);
        cached_server_hello = sh;


        //obtaining the nonce tlv
        tlv* nonce = get_tlv(sh, NONCE);
        //obtaining the certificate signature
        tlv* cert = get_tlv(sh,CERTIFICATE);
        
        //do we need to additionally deserialize the cert
       
        tlv* cert_sig = get_tlv(cert, SIGNATURE);
        // Extract the DNS-Name TLV from the certificate
        tlv* dns_name_tlv = get_tlv(cert, DNS_NAME);
        // Extract the Public Key TLV from the certificate
        tlv* pub_key_cert_tlv = get_tlv(cert, PUBLIC_KEY);

        //extract regular pub key
        tlv* pub_key_tlv = get_tlv(sh, PUBLIC_KEY);

        int data_size = 0;
        uint8_t data[length];

        data_size += serialize_tlv(data + data_size , dns_name_tlv);
        data_size += serialize_tlv(data + data_size, pub_key_cert_tlv);

        //load public key into variable ec_ca_public_key 
        load_ca_public_key("ca_public_key.bin");
        //verify!=1
        //int verify(const uint8_t* signature, size_t sig_size, const uint8_t* data, size_t size, EVP_PKEY* authority);
        //verify if a signature has been signed by an authority
        //exit if not verified
        if (verify(cert_sig->val, cert_sig->length, data, data_size, ec_ca_public_key)!=1) {
            fprintf(stderr, "Error: Certificate signature verification failed!\n");
            //free(data);
            exit(1);
        }
        fprintf(stderr, "Certificate verified\n");


        //check if valid dns name 
        //initially I didn't use strcmp

        if(strcmp((char*)dns_name_tlv->val, cur_host) != 0){
            // Print the DNS name from the certificate and the current host
            fprintf(stderr, "Error: Invalid DNS Name\n");
            fprintf(stderr, "DNS Name from certificate: %s\n", dns_name_tlv->val);
            fprintf(stderr, "Current DNS Host: %s\n", cur_host);
            exit(2);
        }

        fprintf(stderr, "Hostname verified\n");

        tlv* handshake_sig_tlv = get_tlv(sh, HANDSHAKE_SIGNATURE);

        load_peer_public_key(pub_key_cert_tlv->val, pub_key_cert_tlv->length);

        derive_secret();

        if (ec_peer_public_key == NULL) {
            fprintf(stderr, "Error: Public key not loaded correctly.\n");
            exit(1);
        }
        
        fprintf(stderr, "PUBLIC KEY LOADED");

        int offset = 0;

        uint8_t handshake_buffer[length];

        offset += serialize_tlv(handshake_buffer + offset , cached_client_hello);
        offset += serialize_tlv(handshake_buffer + offset, nonce);
        offset += serialize_tlv(handshake_buffer + offset, cert);
        offset += serialize_tlv(handshake_buffer + offset, pub_key_tlv);
        
        if(verify(handshake_sig_tlv->val, handshake_sig_tlv->length,handshake_buffer,offset,ec_peer_public_key)!=1){
            fprintf(stderr, "COULD NOT VERIFY");
            exit(3);
        }

        fprintf(stderr, "handshake verified\n");

        //WORKS UP TILL HANDSHAKE VERIFICATION 

        // Generate the salt (Client-Hello || Server-Hello)
        
        uint16_t salt_s = cached_client_hello->length + cached_server_hello->length + 6;
        uint8_t salt[salt_s]; // Allocate enough space
        uint16_t salt_size = 0;

        // Append cached_client_hello and cached_server_hello to salt buffer 
        salt_size += serialize_tlv(salt + salt_size, cached_client_hello);
        salt_size += serialize_tlv(salt + salt_size, cached_server_hello);
        
        fprintf(stderr, "Expected Salt Size: %d\n", salt_s);
        fprintf(stderr, "Actual Salt Size after serialization: %d\n", salt_size);

        //then derive the ENC key and a MAC key
        derive_keys(salt, salt_s);

        fprintf(stderr, "SALT GENERATED\n");
        

        //working till here
        //now generate finished message
        //void hmac(uint8_t* digest, const uint8_t* data, size_t size);
        //The finished message contains a Transcript, which is the HMAC digest of the Client-Hello with the Server-Hello appended right after.

        tlv* transcript = create_tlv(TRANSCRIPT);
        uint8_t digest[32];

        hmac(digest,salt,salt_size);
        
        add_val(transcript, digest, 32);
       

        //switch to a different state in input 
        //save this code in a global tlv
        finished_message = create_tlv(FINISHED);
        add_tlv(finished_message, transcript);
        

        // uint16_t len = serialize_tlv(buf, finished_message);
        // print_tlv_bytes(buf, length);
        // fprintf(stderr, "FINISHED PRINTING TLV for finished\n");
        client_state  = CLIENT_SEND_FINISHED;
        fprintf(stderr, "CLIENT SENDING FINISHED\n");
        //issue transcript

    }

    

}