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
#include "gateway_server_helper.h"

// globals for server identity and SSL context
struct sockaddr_in address; //server identity (ip address and port)
int addrlen = sizeof(address);
SSL_CTX *ssl_ctx; //SSL server context
int server_fd;


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

    //start the server 
    printf("Starting server on %s:%d\n", ip_address, PORT);
    server_fd = start_server(ip_address);

    // Handle Ctrl+C gracefully
    signal(SIGINT, handle_signal);

    //start accepting connections (TCP and SSL set up)
    while (1) {
        printf("Waiting for incoming connections...\n");
        int new_socket;
        //create TCP connection + accept connection
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
            perror("accept");
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
            exit(0);
        } else {
            //parent process --> responsible to server_fd
            close(new_socket);
        }
    }
    return 0;
}

