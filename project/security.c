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
#define DATA_STATE 8

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

        tlv* nn = create_tlv(NONCE);
        uint8_t nonce[NONCE_SIZE];
        generate_nonce(nonce, NONCE_SIZE); 
        add_val(nn, nonce, NONCE_SIZE);
        add_tlv(ch, nn);

        //derive public/private key pair 
        generate_private_key();
        derive_public_key();

        //generating public key TLV
        tlv* pubkey = create_tlv(PUBLIC_KEY);
        add_val(pubkey, public_key, pub_key_size);
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

        // Append the certificate buffer directly to the Server Hello
        // then we build a tlv for the certificate
        tlv* cert_tlv = create_tlv(CERTIFICATE);
        add_val(cert_tlv, certificate, cert_size);
        add_tlv(sh, cert_tlv);

        //now we generate an "Ephemeral" public key 
        generate_private_key();
        derive_public_key();

        //generating public key TLV
        tlv* pubkey_s = create_tlv(PUBLIC_KEY);
        add_val(pubkey_s, public_key, pub_key_size);
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
        // print_tlv_bytes(handshake_buffer, max_length);
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

        // print_tlv_bytes(buf, max_length);
        
        //free_tlv(sh);
        //free(salt)
       
        server_state = SERVER_HELLO_FINISHED;
        //finish server hello
        return len;
    }

    if (cur_type == CLIENT && client_state == CLIENT_SEND_FINISHED){
       fprintf(stderr, "SENDING HERE");
       uint16_t len = serialize_tlv(buf, finished_message);
       // print_tlv_bytes(buf, max_length);
       client_state = DATA_STATE;
       return len;
    }
    else if ((cur_type == CLIENT || cur_type == SERVER) && (client_state == DATA_STATE || server_state == DATA_STATE)) {
        print("ENTERING DATA STATE");
        tlv* data_tlv = create_tlv(DATA);
        size_t max_plaintext = 943;

        // Read from stdin
        uint8_t plaintext[max_plaintext];
        size_t read_size = read(STDIN_FILENO, plaintext, max_plaintext);

            if (read_size > 0) {
                // Generate IV and encrypt data
                tlv* iv_tlv = create_tlv(IV);
                uint8_t iv[IV_SIZE];
                generate_nonce(iv, IV_SIZE);  // Use the nonce generator for random IV
                add_val(iv_tlv, iv, IV_SIZE);
                add_tlv(data_tlv, iv_tlv);
                
                // Encrypt the data
                uint8_t ciphertext[read_size + 16];  // Add padding space
                size_t cipher_size = encrypt_data(iv, ciphertext, plaintext, read_size);
                
                // Create ciphertext TLV
                tlv* cipher_tlv = create_tlv(CIPHERTEXT);
                add_val(cipher_tlv, ciphertext, cipher_size);
                add_tlv(data_tlv, cipher_tlv);
                
                // Compute HMAC over IV + Ciphertext
                tlv* mac_tlv = create_tlv(MAC);
                uint8_t mac_buffer[IV_SIZE + cipher_size];
                uint8_t mac_digest[MAC_SIZE];
                
                // Create buffer with IV followed by ciphertext
                memcpy(mac_buffer, iv, IV_SIZE);
                memcpy(mac_buffer + IV_SIZE, ciphertext, cipher_size);
                
                // Compute HMAC
                hmac(mac_digest, mac_buffer, IV_SIZE + cipher_size);
                add_val(mac_tlv, mac_digest, MAC_SIZE);
                add_tlv(data_tlv, mac_tlv);
                
                // Serialize the DATA TLV
                uint16_t len = serialize_tlv(buf, data_tlv);
                free_tlv(data_tlv);
                
                return len;
            }
            
            free_tlv(data_tlv);


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

        tlv* sh = deserialize_tlv(buf,length);
        cached_server_hello = sh;

        tlv* nonce = get_tlv(sh, NONCE);
        tlv* cert = get_tlv(sh,CERTIFICATE);
        tlv* cert_sig = get_tlv(cert, SIGNATURE);
        tlv* dns_name_tlv = get_tlv(cert, DNS_NAME);
        tlv* pub_key_cert_tlv = get_tlv(cert, PUBLIC_KEY);

        //extract regular pub key
        tlv* pub_key_tlv = get_tlv(sh, PUBLIC_KEY);

        int data_size = 0;
        uint8_t data[length];

        data_size += serialize_tlv(data + data_size , dns_name_tlv);
        data_size += serialize_tlv(data + data_size, pub_key_cert_tlv);

        load_ca_public_key("ca_public_key.bin");
        //verify if a signature has been signed by an authority
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

        //now loading the peer public key (ephemeral)
        load_peer_public_key(pub_key_tlv->val, pub_key_tlv->length);
        derive_secret();
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

    else if (cur_type == SERVER && server_state == SERVER_HELLO_FINISHED){
        print("TRYING HMAC COMPARISON");
        tlv* finished = deserialize_tlv(buf, length);
        
        if (finished->type != FINISHED) {
            fprintf(stderr, "Error: Expected Finished message but got type 0x%02x\n", finished->type);
            exit(6); 
        }
        tlv* received_transcript = get_tlv(finished, TRANSCRIPT);
        if (received_transcript == NULL) {
            fprintf(stderr, "Error: Transcript not found in Finished message\n");
            exit(6); 
        }
        
        // Get the client's public key and servers private key
        tlv* client_pubkey_tlv = get_tlv(cached_client_hello, PUBLIC_KEY);
        EVP_PKEY* server_ephemeral_key = get_private_key();
        load_peer_public_key(client_pubkey_tlv->val, client_pubkey_tlv->length);
        derive_secret();
        
        // Generate the salt (Client-Hello || Server-Hello)
        uint16_t salt_size = 0;
        uint8_t salt[cached_client_hello->length + cached_server_hello->length + 6]; // +6 for TLV headers
        
        // Serialize Client-Hello and Server-Hello into the salt buffer
        salt_size += serialize_tlv(salt + salt_size, cached_client_hello);
        salt_size += serialize_tlv(salt + salt_size, cached_server_hello);
        
        // Derive the encryption and MAC keys
        derive_keys(salt, salt_size);
        
        // Now calculate our own HMAC digest using the derived MAC key
        uint8_t our_digest[32];
        hmac(our_digest, salt, salt_size);
        if (received_transcript->length != 32 || memcmp(our_digest, received_transcript->val, 32) != 0) {
            fprintf(stderr, "Error: Transcript verification failed\n");
            exit(4); // Bad transcript exit status
        }
        
        fprintf(stderr, "Transcript verified successfully\n");
        free_tlv(finished);
        print("MOVE TO DATA STATE NOW");
        server_state = DATA_STATE;
    }

    else if ((cur_type == CLIENT || cur_type == SERVER) && (client_state == DATA_STATE || server_state == DATA_STATE)) {
        // Deserialize the DATA TLV
        tlv* data_tlv = deserialize_tlv(buf, length);
        
        if (data_tlv->type != DATA) {
            fprintf(stderr, "Error: Expected DATA message but got type 0x%02x\n", data_tlv->type);
            exit(6);  // Unexpected message
        }
        
        // Extract IV, ciphertext, and MAC
        tlv* iv_tlv = get_tlv(data_tlv, IV);
        tlv* cipher_tlv = get_tlv(data_tlv, CIPHERTEXT);
        tlv* mac_tlv = get_tlv(data_tlv, MAC);
        
        if (iv_tlv == NULL || cipher_tlv == NULL || mac_tlv == NULL) {
            fprintf(stderr, "Error: Missing IV, ciphertext, or MAC in DATA message\n");
            exit(6);  // Malformed message
        }
        
        // Verify MAC
        uint8_t* iv = iv_tlv->val;
        uint8_t* ciphertext = cipher_tlv->val;
        uint8_t* received_mac = mac_tlv->val;
        
        // Create buffer with IV followed by ciphertext for MAC verification
        uint8_t mac_buffer[iv_tlv->length + cipher_tlv->length];
        uint8_t computed_mac[MAC_SIZE];
        
        memcpy(mac_buffer, iv, iv_tlv->length);
        memcpy(mac_buffer + iv_tlv->length, ciphertext, cipher_tlv->length);
        
        // Compute HMAC
        hmac(computed_mac, mac_buffer, iv_tlv->length + cipher_tlv->length);
        
        // Verify MAC

        if (memcmp(computed_mac, received_mac, MAC_SIZE) != 0) {
            fprintf(stderr, "Error: MAC verification failed\n");
            exit(5);  // Bad MAC
        }

        // if (mac_tlv->length != MAC_SIZE || memcmp(computed_mac, received_mac, MAC_SIZE) != 0) {
        //     fprintf(stderr, "Error: MAC verification failed\n");
        //     exit(5);  // Bad MAC
        // }
        
        // Decrypt data
        uint8_t plaintext[cipher_tlv->length];  // Plaintext will be smaller than ciphertext
        size_t plaintext_size = decrypt_cipher(plaintext, ciphertext, cipher_tlv->length, iv);
        
        // Write to stdout
        write(STDOUT_FILENO, plaintext, plaintext_size);
        
        free_tlv(data_tlv);
    }
}