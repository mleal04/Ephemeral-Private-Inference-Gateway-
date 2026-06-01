#ifndef WORKER_PROCESS_H
#define WORKER_PROCESS_H
#include <openssl/ssl.h>

extern void ShutdownSSL(SSL *cSSL);

void pcc_node_logic(SSL *cSSL, int new_socket);
void pcc_attestion(char *response_buffer);

#endif // WORKER_PROCESS_H