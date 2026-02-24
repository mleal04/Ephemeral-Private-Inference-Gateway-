#ifndef IPC_UTILS_H
#define IPC_UTILS_H

// int create_message_queue();
void send_to_worker(int pipefd, char *request_buffer, int bytes)

#endif // IPC_UTILS_H