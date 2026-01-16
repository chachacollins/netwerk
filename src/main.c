#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
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

#define error_defer(func)                                                                      \
    do                                                                                         \
    {                                                                                          \
       if((func) < 0)                                                                          \
       {                                                                                       \
           fprintf(stderr, "ERROR:" __FILE__ ":%d:" #func " %s\n", __LINE__, strerror(errno)); \
           result = -1;                                                                        \
           goto defer;                                                                         \
       }                                                                                       \
    }                                                                                          \
    while(0)

typedef struct {
    char* data;
    size_t len;
    size_t capacity;
} String;

void string_append(String *string, char* data)
{
    size_t data_len = strlen(data);
    if(data_len + string->len + 1> string->capacity)
    {
        size_t new_capacity = data_len + string->len + 1 + string->capacity * 2;
        char* new_pointer = realloc(string->data, new_capacity);
        assert(new_pointer);
        string->data = new_pointer;
        string->capacity = new_capacity;
    }
    strcat(string->data, data); 
    string->len += data_len;
}

void string_free(String *string)
{
    free(string->data);
    string->data = NULL;
    string->capacity = 0;
    string->len = 0;
}

char* string_to_cstr(String *string)
{
    char* buffer = malloc(string->len + 1);
    assert(buffer);
    *(char*)mempcpy(buffer, string->data, string->len) = '\0';
    return buffer;
}

[[nodiscard]]
int process_request(int client_fd)
{
    int result = 0;
	printf("Client connected\n");
    char buffer[1024] = {0};
    error_defer(recv(client_fd, buffer, sizeof(buffer), 0));
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
        error_defer(send(client_fd, resp_s, strlen(resp_s), 0));
    }
    else if(strncmp(req_target, "/echo/", 6) == 0)
    {
        strtok(req_target, "/");
        char* echo_message = strtok(NULL, "/");
        if(!echo_message) echo_message = "";

        String resp = {0};
        string_append(&resp, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n");
        char content_len[1024] = {0};
        sprintf(content_len, "Content-Length: %zu\r\n\r\n", strlen(echo_message));
        string_append(&resp, content_len);
        string_append(&resp, echo_message);
        char* resp_e = string_to_cstr(&resp);

        error_defer(send(client_fd, resp_e, strlen(resp_e), 0));

        free(resp_e);
        string_free(&resp);
    }
    else
    {
        printf("request target %s not found\n", req_target);
        char resp_f[] = "HTTP/1.1 404 Not Found\r\n\r\n";
        error_defer(send(client_fd, resp_f, strlen(resp_f), 0));
    }
	printf("response message sent\n");
defer:
    close(client_fd);
    printf("Connection closed\n");
    return result;
}

int main() {
    int server_fd = 0, result = 0;
    unsigned int client_addr_len;

	struct sockaddr_in client_addr;
	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd == -1) {
		printf("Socket creation failed: %s...\n", strerror(errno));
		return 1;
	}
	int reuse = 1;
	error_defer(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)));

	struct sockaddr_in serv_addr = { .sin_family = AF_INET ,
									 .sin_port = htons(4221),
									 .sin_addr = { htonl(INADDR_ANY) },
									};
	error_defer(bind(server_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)));

	int connection_backlog = 5;
	error_defer(listen(server_fd, connection_backlog));
    printf("Listening on port: 4221\n");

	printf("Waiting for a client to connect...\n");
	client_addr_len = sizeof(client_addr);
    while(true)
    {
        int client_fd;
        if((client_fd = accept(server_fd, (struct sockaddr *) &client_addr, &client_addr_len)) < 0)
        {
            printf("Failed to accept connection: %s\n", strerror(errno));
            continue;
        }
        printf("Connection Accepted fd = %d\n", client_fd);
        if(process_request(client_fd) < 0)
        {
            printf("Failed to process connection\n");
        }
    }
defer:
    if(server_fd)
    {
        close(server_fd);
    }
	return result;
}
