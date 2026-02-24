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

void pcc_node_logic(SSL *cSSL, int new_socket) {
    char request_buffer[BUFSIZ];
    int bytes = SSL_read(cSSL, request_buffer, sizeof(request_buffer));
    request_buffer[bytes] = '\0';
    //send request to right right nodes fucntions 


    //SSL write response back to client
    char *response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello from the PCC node!";
    SSL_write(cSSL, response, strlen(response));
    ShutdownSSL(cSSL);
    close(new_socket);
}