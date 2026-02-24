#ifndef IPC_UTILS_H
#define IPC_UTILS_H

// int create_message_queue();
void send_to_worker(int pipefd, char *request_buffer, int bytes);
void read_from_worker(int pipefd, char *response_buffer, int buffer_size);

#endif // IPC_UTILS_H