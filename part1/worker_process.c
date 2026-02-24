#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void handle_worker_logic(int pipefd) {
    char request_buffer[BUFSIZ];
    char response_buffer[BUFSIZ];

    // Read request from parent process
    read_from_worker(pipefd, request_buffer, sizeof(request_buffer));

}