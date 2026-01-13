#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define check_error(func)                                                          \
      do {                                                                         \
        if ((func) < 0) {                                                          \
            printf("Failed " #func " %s\n", strerror(errno));                      \
            return 0;                                                              \
        }                                                                          \
      } while (0)

[[nodiscard]]
int process_request(int client_fd)
{
    int result;
	printf("Client connected\n");
    char buffer[1024] = {0};
    check_error(recv(client_fd, buffer, sizeof(buffer), 0));
    char* req_line = strtok(buffer, "\r\n");
    printf("req_line   = %s\n",req_line);
    char* req_method = strtok(req_line, " ");
    char* req_target = strtok(NULL, " ");
    char* http_vers = strtok(NULL,  " ");

    printf("req_method = %s\n",req_method);
    printf("req_target = %s\n",req_target);
    printf("http_vers  = %s\n",http_vers);

    if(strcmp(req_target, "/") == 0)
    {
        char resp_s[] = "HTTP/1.1 200 OK\r\n\r\n";
        check_error(send(client_fd, &resp_s, strlen(resp_s), 0));
    }
    else
    {
        char resp_f[] = "HTTP/1.1 404 Not Found\r\n\r\n";
        check_error(send(client_fd, &resp_f, strlen(resp_f), 0));
    }
	printf("response message sent\n");
    return 1;
}

int main() {
	// Disable output buffering
	setbuf(stdout, NULL);
 	setbuf(stderr, NULL);

    int server_fd, result = 0;
    unsigned int client_addr_len;
	struct sockaddr_in client_addr;
	//
	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd == -1) {
		printf("Socket creation failed: %s...\n", strerror(errno));
		return 1;
	}
	int reuse = 1;
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
		printf("SO_REUSEADDR failed: %s \n", strerror(errno));
		return 1;
	}

	struct sockaddr_in serv_addr = { .sin_family = AF_INET ,
									 .sin_port = htons(4221),
									 .sin_addr = { htonl(INADDR_ANY) },
									};

	if (bind(server_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) != 0) {
		printf("Bind failed: %s \n", strerror(errno));
		return 1;
	}

	int connection_backlog = 5;
	if (listen(server_fd, connection_backlog) != 0) {
		printf("Listen failed: %s \n", strerror(errno));
		return 1;
	}
    printf("Listening on port: 4221\n");

	printf("Waiting for a client to connect...\n");
	client_addr_len = sizeof(client_addr);
    while(true)
    {
        int client_fd;
        if((client_fd = accept(server_fd, (struct sockaddr *) &client_addr, &client_addr_len)) < 0)
        {
            printf("Failed to accept connection: %s\n", strerror(errno));
            return 1;
        }
        if(!process_request(client_fd))
        {
            printf("Failed to process connection\n");
            result = 1;
        }
        close(client_fd);
    }

    close(server_fd);
	printf("Connection closed\n");

	return 1;
}
