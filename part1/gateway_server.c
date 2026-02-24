#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <arpa/inet.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

//helper functions for the gateway server
#include "worker_process.h"

//server port and server identity + SSL server context
#define PORT 8443  //HTTPS default port
struct sockaddr_in address; //server identity (ip address and port)
int addrlen = sizeof(address);
SSL_CTX *ssl_ctx; //SSL server context

int main(int argc, char *argv[]) {
    //check for inputs before starting the server
    if (argc != 2) {
        printf("No IP address provided.");
        return 1;
    }
    char *ip_address = argv[1];

    // setup SSL for the server
    int flag = setup_SSL();
    if (flag != 0) {
        return 1; // exit if SSL setup failed
    }

    //start the server --> ip_address, port 443, https, tcp
    printf("Starting server on %s:%d\n", ip_address, PORT);
    int server_fd = start_server(ip_address);

    //start accepting connections (TCP and SSL set up)
    while (1) {
        printf("Waiting for incoming connections...\n");
        int new_socket;
        //create TCP connection  
        if (accept_connection(server_fd, &new_socket) < 0) {
            continue; // move to next connection
        }
        // create SSL connection over TCP
        SSL *cSSL = add_TLS_to_socket(new_socket);
        if (cSSL == NULL) {
            continue; // move to next connection
        }
        // fork process and hand off to pcc node
        pid_t pid = fork();
        if (pid < 0) {
            perror("Fork failed");
            ShutdownSSL(cSSL);
            close(new_socket);
            continue; // move to next connection
        } else if (pid == 0) {
            //child process --> responsible to cSSL and new_socket
            close(server_fd); 
            pcc_node_logic(cSSL, new_socket);
        } else {
            //parent process --> responsible to server_fd
            ShutdownSSL(cSSL);
            close(new_socket);
        }
    }
    return 0;
}

int setup_SSL() {
    // create SSL context for the server
    InitializeSSL();

    // create tls context 
    ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ssl_ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    // set TLS options --> for encryption and security
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    // load the server certificate and private key
    if (SSL_CTX_use_certificate_file(ssl_ctx, "./certs_keys/cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ssl_ctx, "./certs_keys/server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ssl_ctx);
        return 1;
    }

    // check that the private key matches the certificate
    if (!SSL_CTX_check_private_key(ssl_ctx)) {
    fprintf(stderr, "Private key does not match the certificate\n");
    SSL_CTX_free(ssl_ctx);
    return 1;
    }

    return 0;
}

// set up TCP server + get ready to accept SSL connections
int start_server(char *ip_address) {
    int server_fd;
    int opt = 1;

    //create the socket type for the server --> ipv4, tcp
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // forcefully attaching socket to the port 443 --> for https
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // define the servers identity
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(ip_address);
    address.sin_port = htons(PORT);

    // bind socket to the server identity
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    //start listening for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    printf("Server listening on %s:%d\n", ip_address, PORT);

    return server_fd;
}

SSL *add_TLS_to_socket(int new_socket) {
    // create the TLS session for this client tcp connection 
    SSL *cSSL = SSL_new(ssl_ctx);
    if (!cSSL) {
        ERR_print_errors_fp(stderr);
        close(new_socket);
        return NULL; // move to next connection
    }

    // attach TLS to the TCP socket
    SSL_set_fd(cSSL, new_socket);

    // perform TLS handshake
    if (SSL_accept(cSSL) <= 0) {
        ERR_print_errors_fp(stderr);
        ShutdownSSL(cSSL);
        close(new_socket);
        return NULL; // move to next connection
    }
    return cSSL;
}

void InitializeSSL()
{
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
}

void DestroySSL()
{
    ERR_free_strings();
    EVP_cleanup();
}

void ShutdownSSL(SSL *cSSL)
{
    SSL_shutdown(cSSL);
    SSL_free(cSSL);
}

