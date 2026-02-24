#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void send_to_worker(int pipefd, char *request_buffer, int bytes) {
    write(pipefd, request_buffer, bytes);
}

void read_from_worker(int pipefd, char *response_buffer, int buffer_size) {
    int bytes_read = read(pipefd, response_buffer, buffer_size);
    if (bytes_read < 0) {
        perror("read");
        exit(EXIT_FAILURE);
    }
    response_buffer[bytes_read] = '\0';  // Null-terminate the response
}