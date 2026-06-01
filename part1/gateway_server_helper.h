#ifndef GATEWAY_SERVER_HELPER_H
#define GATEWAY_SERVER_HELPER_H

#include <netinet/in.h>
#include <openssl/ssl.h>

#define PORT 8443  

// Declare globals for the linker
extern struct sockaddr_in address;
extern int addrlen;
extern SSL_CTX *ssl_ctx;
extern int server_fd;

// Function declarations
void handle_signal(int sig);
int setup_SSL();
int start_server(char *ip_address);
SSL *add_TLS_to_socket(int new_socket);
void InitializeSSL();
void DestroySSL();
void ShutdownSSL(SSL *cSSL);

#endif // GATEWAY_SERVER_HELPER_H