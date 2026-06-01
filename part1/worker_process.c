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
    int bytes = SSL_read(cSSL, request_buffer, sizeof(request_buffer) - 1);
    if (bytes <= 0) {
        ShutdownSSL(cSSL);
        close(new_socket);
        return;
    }
    request_buffer[bytes] = '\0';

    char response[BUFSIZ];

    // attestation Key Request
    if (strstr(request_buffer, "/attestation") != NULL) {
        pcc_attestion(response);
    } 
    // final inference request from the relay
    else if (strstr(request_buffer, "/inference") != NULL) {
        char *http_body = strstr(request_buffer, "\r\n\r\n");
        if (http_body != NULL) {
            http_body += 4; 
            printf("\n[GATEWAY] Success! Received Base64 Payload from Relay:\n%s\n\n", http_body);
            //  HERE GATEWAY WOULD DECRYPT WITH REK.PRIV.KEY --> DECRYPTING DEK
            // THEN WE WOULD USE THE DEK TO DECRYPT THE ACTUAL MESSAGE AT THE NODE LEVEL
            char server_reply[] = "hello from server! Proxy routing loop successfully validated.";
            // HERE WE WOULD ENCRYPT THE RESPONSE WITH THE DEK AND SEND IT BACK TO THE RELAY
            // AND MOST IMPORTANTLY: EPHEMERALITY IS PRESERVED BECAUSE THE DEK IS NEVER STORED AND IS ONLY USED FOR THIS SINGLE INFERENCE REQUEST
            snprintf(response, sizeof(response),
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/plain\r\n"
                    "Content-Length: %lu\r\n"
                    "\r\n"
                    "%s", 
                    strlen(server_reply), server_reply);
        } else {
            char err_msg[] = "Inference Error: Missing request body payload.";
            snprintf(response, sizeof(response), "HTTP/1.1 400 Bad Request\r\nContent-Length: %lu\r\n\r\n%s", strlen(err_msg), err_msg);
        }
    } 
    // Fallback handler
    else {
        snprintf(response, sizeof(response),
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 25\r\n\r\nHello from the PCC node!");
    }

    SSL_write(cSSL, response, strlen(response));
    ShutdownSSL(cSSL);
    close(new_socket);
}