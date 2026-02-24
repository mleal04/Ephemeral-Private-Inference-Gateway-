#ifndef WORKER_PROCESS_H
#define WORKER_PROCESS_H
#include <openssl/ssl.h>

void pcc_node_logic(SSL *cSSL, int new_socket);

#endif // WORKER_PROCESS_H