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

#include "worker_process.h"


void pcc_attestion(char *response_buffer) {
    char *rek_pub_key = getenv("rek_pub_key");
    if (rek_pub_key != NULL) {
        snprintf(response_buffer, BUFSIZ,
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/x-pem-file\r\n"
                "Content-Length: %lu\r\n"
                "\r\n"
                "%s", 
                strlen(rek_pub_key), rek_pub_key);
    } else {
        snprintf(response_buffer, BUFSIZ,
                "HTTP/1.1 500 Internal Server Error\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: %lu\r\n"
                "\r\n"
                "Failed to load REK.", 
                strlen("Failed to load REK."));
    }
}


void pcc_node_logic(SSL *cSSL, int new_socket) {
    char request_buffer[BUFSIZ];
    int bytes = SSL_read(cSSL, request_buffer, sizeof(request_buffer));
    request_buffer[bytes] = '\0';
    printf("%s\n", request_buffer);

    //check for variety of requests and respond accordingly
    char response[BUFSIZ];

    char *prefix = "/attestation";
    // Change strncmp to strstr
    if (strstr(request_buffer, prefix) != NULL) {
        pcc_attestion(response); // Make sure to pass your buffer size!
    } else {
        snprintf(response, sizeof(response),
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello from the PCC node!");
    }

    //SSL write response back to client
    SSL_write(cSSL, response, strlen(response));
    ShutdownSSL(cSSL);
    close(new_socket);
}