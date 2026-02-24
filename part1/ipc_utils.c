#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void send_to_worker(int pipefd, char *request_buffer, int bytes) {
    write(pipefd, request_buffer, bytes);
}