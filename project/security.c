#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

// We'll define states for the client and server
#define CLIENT_INIT        0
#define CLIENT_CH_SENT     1
#define CLIENT_SH_VERIFIED 2
#define CLIENT_FINISHED_SENT 3
#define CLIENT_DONE        4

#define SERVER_INIT        0
#define SERVER_SH_SENT     1
#define SERVER_FINISHED_OK 2

// We'll store the role (client/server), the states, and the hostname (for DNS check)
static int g_role = -1;        // CLIENT or SERVER
static int g_client_state = CLIENT_INIT;
static int g_server_state = SERVER_INIT;
static char* g_hostname = NULL;

// We'll store the raw Client Hello and raw Server Hello for the transcript
static uint8_t g_client_hello_raw[2048];
static size_t  g_client_hello_len = 0;

static uint8_t g_server_hello_raw[2048];
static size_t  g_server_hello_len = 0;


// Prototypes for our local helpers
static void handle_server_hello_on_client(uint8_t* buf, size_t length);
static void handle_finished_on_server(uint8_t* buf, size_t length);

// Initialize
void init_sec(int type, char* host) {
    init_io();
    g_role = type;
    if (host) {
        g_hostname = strdup(host);
    }
    // Set up states
    if (g_role == CLIENT) {
        g_client_state = CLIENT_INIT;
    } else {
        g_server_state = SERVER_INIT;
    }
}

// input_sec: called by the transport layer when it needs data to send
ssize_t input_sec(uint8_t* buf, size_t max_length) {
    if (g_role == CLIENT) {
        if (g_client_state == CLIENT_INIT) {
            print("------- CLIENT INIT ---------");
            // ---------- Build Client Hello -----------
            tlv* client_hello = create_tlv(CLIENT_HELLO);

            // NONCE (0x01)
            tlv* nonce_tlv = create_tlv(NONCE);
            uint8_t nonce[NONCE_SIZE];
            generate_nonce(nonce, NONCE_SIZE);
            add_val(nonce_tlv, nonce, NONCE_SIZE);
            add_tlv(client_hello, nonce_tlv);

            // ephemeral key
            generate_private_key();
            derive_public_key(); // -> global public_key, pub_key_size
            tlv* pub_tlv = create_tlv(PUBLIC_KEY);
            add_val(pub_tlv, public_key, pub_key_size);
            add_tlv(client_hello, pub_tlv);

            // serialize
            uint16_t ch_len = serialize_tlv(buf, client_hello);
            // save raw
            memcpy(g_client_hello_raw, buf, ch_len);
            g_client_hello_len = ch_len;
            print_tlv_bytes(buf, ch_len);
            free_tlv(client_hello);
            fprintf(stderr, "SEND CLIENT HELLO\n");
            g_client_state = CLIENT_CH_SENT;
            return ch_len;
        }
        // else pass through
        return input_io(buf, max_length);

    } else {
        // SERVER side
        // We wait until we have the client hello (in output_sec), then build Server Hello
        if (g_server_state == SERVER_INIT && g_client_hello_len > 0) {
            // ---------- Build Server Hello ----------
            tlv* server_hello = create_tlv(SERVER_HELLO);

            // NONCE
            tlv* sn_tlv = create_tlv(NONCE);
            uint8_t s_nonce[NONCE_SIZE];
            generate_nonce(s_nonce, NONCE_SIZE);
            add_val(sn_tlv, s_nonce, NONCE_SIZE);
            add_tlv(server_hello, sn_tlv);

            // load server cert, parse as a TLV
            load_certificate("server_cert.bin");
            tlv* cert_parsed = deserialize_tlv(certificate, cert_size);
            add_tlv(server_hello, cert_parsed);

            // ephemeral key
            generate_private_key();
            derive_public_key();
            tlv* ephemeral_pub = create_tlv(PUBLIC_KEY);
            add_val(ephemeral_pub, public_key, pub_key_size);
            add_tlv(server_hello, ephemeral_pub);
            print("PRINTITNG EPHEMEMRAL PUBLCI KEY SERVEWR");
            print_tlv_bytes(ephemeral_pub->val, ephemeral_pub->length);
            print("END OF EPEHREMEAL PIBLVI KEY");
            // sign data = [client hello raw (TLV) + s_nonce + cert + ephemeral_pub]
            uint8_t sign_data[4096];
            size_t off = 0;
            // first parse the cached client hello to a TLV so we can re-serialize
            tlv* ch_tlv = deserialize_tlv(g_client_hello_raw, g_client_hello_len);
            if (!ch_tlv) {
                fprintf(stderr, "No valid client hello\n");
                return -1;
            }
            off += serialize_tlv(sign_data + off, ch_tlv);
            off += serialize_tlv(sign_data + off, sn_tlv);
            off += serialize_tlv(sign_data + off, cert_parsed);
            off += serialize_tlv(sign_data + off, ephemeral_pub);

            EVP_PKEY* ephemeral_priv = get_private_key();
            load_private_key("server_key.bin");
            EVP_PKEY* perm_key = get_private_key();
            set_private_key(perm_key);

            uint8_t signature[256];
            size_t sig_len = sign(signature, sign_data, off);

            set_private_key(ephemeral_priv);

            tlv* handshake_sig = create_tlv(HANDSHAKE_SIGNATURE);
            add_val(handshake_sig, signature, sig_len);
            add_tlv(server_hello, handshake_sig);

            // serialize
            uint16_t sh_len = serialize_tlv(buf, server_hello);
            memcpy(g_server_hello_raw, buf, sh_len);
            g_server_hello_len = sh_len;
            print_tlv_bytes(buf, sh_len);
            free_tlv(server_hello);
            free_tlv(ch_tlv);

            fprintf(stderr, "SEND SERVER HELLO\n");
            g_server_state = SERVER_SH_SENT;
            return sh_len;
        }
        return input_io(buf, max_length);
    }
}

// output_sec: called when data arrives from the transport
void output_sec(uint8_t* buf, size_t length) {
    output_io(buf, length);

    if (g_role == SERVER) {
        // we parse inbound messages from the client
        tlv* inbound = deserialize_tlv(buf, length);
        if (!inbound) return;

        if (inbound->type == CLIENT_HELLO && g_server_state == SERVER_INIT) {
            // store the raw client hello
            memcpy(g_client_hello_raw, buf, length);
            g_client_hello_len = length;
            fprintf(stderr, "RECV CLIENT HELLO\n");
        }
        else if (inbound->type == FINISHED && g_server_state == SERVER_SH_SENT) {
            // Client is sending finished
            fprintf(stderr, "RECV FINISHED\n");
            // parse the transcript Tlv
            tlv* transcript_tlv = get_tlv(inbound, TRANSCRIPT);
            if (!transcript_tlv || transcript_tlv->length != MAC_SIZE) {
                fprintf(stderr, "Finished is malformed\n");
                exit(6);
            }
            // compute local transcript = HMAC over [clientHello raw + serverHello raw]
            size_t total = g_client_hello_len + g_server_hello_len;
            uint8_t* salt = malloc(total);
            memcpy(salt, g_client_hello_raw, g_client_hello_len);
            memcpy(salt + g_client_hello_len, g_server_hello_raw, g_server_hello_len);

            uint8_t local_digest[MAC_SIZE];
            hmac(local_digest, salt, total);
            free(salt);

            // comparea
            if (memcmp(local_digest, transcript_tlv->val, MAC_SIZE) != 0) {
                fprintf(stderr, "Transcript mismatch => exit(4)\n");
                exit(4);
            }
            fprintf(stderr, "Finished valid => handshake done\n");
            g_server_state = SERVER_FINISHED_OK;
        }
        free_tlv(inbound);

    } else {
        // we parse inbound from the server
// we parse inbound from the server
        tlv* inbound = deserialize_tlv(buf, length);
        if (!inbound) return;

        if (inbound->type == SERVER_HELLO && g_client_state == CLIENT_CH_SENT) {
            
            fprintf(stderr, "RECV SERVER HELLO\n");
            // store raw
            memcpy(g_server_hello_raw, buf, length);
            g_server_hello_len = length;

            // parse the server hello
            tlv* sh = inbound;
            
            // 1. Extract components from the server hello
            tlv* server_nonce = get_tlv(sh, NONCE);
            tlv* certificate_tlv = get_tlv(sh, CERTIFICATE);
            tlv* server_public_key = get_tlv(sh, PUBLIC_KEY);
            tlv* signature_tlv = get_tlv(sh, HANDSHAKE_SIGNATURE);
            print("server oubliv key");
            print_tlv_bytes(server_public_key->val, server_public_key->length);
            if (!server_nonce || !certificate_tlv || !server_public_key || !signature_tlv) {
                fprintf(stderr, "Server Hello missing required components\n");
                exit(6);
            }
            
            // 2. Verify the certificate
            // 2.1 Load the CA public key
            load_ca_public_key("ca_public_key.bin");
            
            // 2.2 Parse the certificate
            tlv* cert = certificate_tlv;
            tlv* dns_name = get_tlv(cert, DNS_NAME);
            tlv* cert_public_key = get_tlv(cert, PUBLIC_KEY);
            tlv* cert_signature = get_tlv(cert, SIGNATURE);
            
            if (!dns_name || !cert_public_key || !cert_signature) {
                fprintf(stderr, "Certificate is malformed\n");
                exit(1);
            }
            
            // 2.3 Verify the certificate signature
            // Concatenate DNS name and public key
            uint8_t* verify_data = malloc(dns_name->length + cert_public_key->length + 4);
            size_t verify_offset = 0;
            
            verify_offset += serialize_tlv(verify_data + verify_offset, dns_name);
            verify_offset += serialize_tlv(verify_data + verify_offset, cert_public_key);
            
            // Verify the certificate signature using the CA's public key
            int cert_valid = verify(cert_signature->val, cert_signature->length, 
                                verify_data, verify_offset, ec_ca_public_key);
            free(verify_data);
            
            if (cert_valid != 1) {
                fprintf(stderr, "Certificate signature verification failed => exit(1)\n");
                exit(1);
            }
            
            // 3. Verify the DNS name
            if (memcmp(dns_name->val, g_hostname, dns_name->length) != 0) {
                    fprintf(stderr, "DNS name does not match => exit(2)\n");
                    exit(2);
            }
            
            // 4. Verify the server hello signature
            // 4.1 Extract the server's public key from the certificate
            load_peer_public_key(cert_public_key->val, cert_public_key->length);
            
            // 4.2 Construct the data that was signed
            uint8_t* signed_data = malloc(g_client_hello_len + server_nonce->length + 
                                        certificate_tlv->length + server_public_key->length + 8);
            size_t signed_offset = 0;
            
            // Reconstruct the data that was signed: client_hello + server_nonce + certificate + server_public_key
            memcpy(signed_data, g_client_hello_raw, g_client_hello_len);
            signed_offset += g_client_hello_len;
            
            signed_offset += serialize_tlv(signed_data + signed_offset, server_nonce);
            signed_offset += serialize_tlv(signed_data + signed_offset, certificate_tlv);
            signed_offset += serialize_tlv(signed_data + signed_offset, server_public_key);
            
            // 4.3 Verify the server hello signature
            int sig_valid = verify(signature_tlv->val, signature_tlv->length,
                                signed_data, signed_offset, ec_peer_public_key);
            free(signed_data);
            
            if (sig_valid != 1) {
                fprintf(stderr, "Server Hello signature verification failed => exit(3)\n");
                exit(3);
            }
            
            // 5. Now that verification is complete, derive the shared secret
            // 5.1 Save the server's ephemeral public key
            load_peer_public_key(server_public_key->val, server_public_key->length);
            
            // 5.2 Derive the shared secret
            derive_secret();
            
            // 5.3 Derive the ENC and MAC keys
            
            // Salt is the Client-Hello with the Server-Hello appended right after
            size_t salt_len = g_client_hello_len + g_server_hello_len;
            uint8_t* salt = malloc(salt_len);
            memcpy(salt, g_client_hello_raw, g_client_hello_len);
            memcpy(salt + g_client_hello_len, g_server_hello_raw, g_server_hello_len);
            derive_keys(salt, salt_len);
            print("PRINTING MA SALT NOWW");
            print_tlv_bytes(salt, salt_len);
           
            uint8_t digest[MAC_SIZE];
            hmac(digest, salt, salt_len);
            

            tlv* t_tlv = create_tlv(TRANSCRIPT);
            add_val(t_tlv, digest, MAC_SIZE);
            tlv* finished = create_tlv(FINISHED);
            add_tlv(finished, t_tlv);

            uint8_t fin_buf[256];
            uint16_t fin_len = serialize_tlv(fin_buf, finished);
            free(salt);
            free_tlv(finished);
            print("PRINTING A FINISH MESSAGE");
            print_tlv_bytes(fin_buf, fin_len);
            fprintf(stderr, "SEND FINISHED\n");
            output_io(fin_buf, fin_len);

            g_client_state = CLIENT_FINISHED_SENT;
        }
        else {
            // Maybe it's normal data or something else
            if (inbound) free_tlv(inbound);
        }
    }
}
