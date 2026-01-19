#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>

#define STI_IMPLEMENTATION
#include "sti.h"

volatile sig_atomic_t running = 1;

typedef enum
{
    LOG_KIND_ERROR,
    LOG_KIND_WARNING,
    LOG_KIND_SUCCESS,
    LOG_KIND_INFO,
} LOG_KIND;

void log_fmt(LOG_KIND kind, char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    switch(kind)
    {
        case LOG_KIND_ERROR  : fprintf(stderr, "[ERROR]: "); break;
        case LOG_KIND_WARNING: fprintf(stderr, "[WARNING]: "); break;
        case LOG_KIND_SUCCESS: fprintf(stderr, "[SUCCESS]: "); break;
        case LOG_KIND_INFO   : fprintf(stderr, "[INFO]: "); break;
        default: assert(0 && "Unreachable");
    }
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

#define error_defer(func)                                                                      \
    do                                                                                         \
    {                                                                                          \
       if((func) < 0)                                                                          \
       {                                                                                       \
           log_fmt(LOG_KIND_ERROR,__FILE__ ":%d:" #func " %s\n", __LINE__, strerror(errno));   \
           result = -1;                                                                        \
           goto defer;                                                                         \
       }                                                                                       \
    }                                                                                          \
    while(0)

int send_plain_text(Arena* arena, int client_fd, const char* res)
{
    int result = 0;
    String resp = {0};
    string_concat_cstr(arena, &resp, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n");
    char content_len[1024] = {0};
    sprintf(content_len, "Content-Length: %zu\r\n\r\n", strlen(res));
    string_concat_cstr(arena, &resp, content_len);
    string_concat_cstr(arena, &resp, res);
    char* resp_e = string_to_cstr(arena, &resp);

    error_defer(send(client_fd, resp_e, strlen(resp_e), 0));
defer:
    return result;
}

char* trim_left(char* s)
{
    while(isspace(*s)) s++;
    return s;
}

typedef struct
{
    char* key;
    char* value;
} Header;

typedef struct
{
    char* method;
    char* version;
    char* target;
    Header* headers;
    char* content;
} Request;

#define HEADER_TABLE_MAX 20

Header* hm_init(Arena* arena)
{
    Header* hm = arena_alloc(arena, sizeof(Header) * HEADER_TABLE_MAX); 
    memset(hm, 0, sizeof(Header) * HEADER_TABLE_MAX);
    return hm;
}

//NOTE: the length is assumed to be at least 2
uint32_t hash(const char* key, size_t len)
{
    return ((uint32_t)(*(uint16_t*)key) << 16) | *(uint16_t*)(key+(len-2));
}

int hm_insert(Header* hm, Header header)
{
    uint32_t i_index = hash(header.key, strlen(header.key)) % HEADER_TABLE_MAX;
    for(uint32_t i = 0; i < HEADER_TABLE_MAX; i++)
    {
        uint32_t index = (i_index + i) % HEADER_TABLE_MAX;
        Header *slot = &hm[index];
        if(slot->key != NULL) continue;
        *slot = header;
        return 0;
    }
    return -1;
}

Header* hm_get(Header* hm, const char* key)
{
    int i_index = hash(key, strlen(key)) % HEADER_TABLE_MAX;
    for(int i = 0; i < HEADER_TABLE_MAX; i++)
    {
        int index = (i_index + i) % HEADER_TABLE_MAX;
        Header *slot = &hm[index];
        if(slot->key == NULL) return NULL;
        if(*key == *slot->key && strcmp(slot->key, key) == 0) return slot;
    }
    return NULL;
}

void hm_display(Header* hm)
{
    for(int i = 0; i < HEADER_TABLE_MAX; i++)
    {
        Header h = hm[i];
        printf("%s => %s\n", h.key, h.value);
    }
}

char* to_lower(char* s)
{
    int len = strlen(s);
    for(int i = 0; i < len; i++)
    {
        if(isalpha(s[i]))
            s[i] = tolower(s[i]);
    }
    return s;
}

int parse_request(Arena* arena, Request* request, char* buffer)
{
    int result = 0;
    request->headers = hm_init(arena);
    char* req_line = strtok(buffer, "\r\n");
    if (!req_line) return -1;
    char* line = strtok(NULL, "\r\n");
    while (line != NULL)
    {
        char* colon = strchr(line, ':');
        if (colon) 
        {
            *colon = '\0'; 
            char* key = to_lower(line);
            char* val = trim_left(colon + 1);
            error_defer(hm_insert(request->headers, (Header){key, val}));
        }
        line = strtok(NULL, "\r\n");
    }
    request->method  =  strtok(req_line, " ");
    request->target  =  strtok(NULL, " ");
    request->version =  strtok(NULL, " ");
    request->content = NULL;

defer:
    return result;
}

int process_request(int client_fd)
{
    Arena arena = {0};
    int result = 0;
	log_fmt(LOG_KIND_INFO, "Client connected");
    char buffer[1024] = {0};
    error_defer(recv(client_fd, buffer, sizeof(buffer), 0));
    Request request = {0};
    error_defer(parse_request(&arena, &request, buffer));
    if(strcmp(request.target, "/") == 0)
    {
        char resp_s[] = "HTTP/1.1 200 OK\r\n\r\n";
        error_defer(send(client_fd, resp_s, strlen(resp_s), 0));
    }
    else if(strncmp(request.target, "/echo/", 6) == 0)
    {
        //NOTE: discard the request target because we already hit the endpoint
        (void)strtok(request.target, "/");
        char* echo_message = strtok(NULL, "/");
        if(!echo_message) echo_message = "";
        error_defer(send_plain_text(&arena, client_fd, echo_message));
    }
    else if(strncmp(request.target, "/user-agent", 11) == 0)
    {
        Header* user_agent = hm_get(request.headers, "user-agent");
        assert(user_agent);
        error_defer(send_plain_text(&arena, client_fd, user_agent->value));
    }
    else
    {
        log_fmt(LOG_KIND_ERROR, "request target %s not found", request.target);
        char resp_f[] = "HTTP/1.1 404 Not Found\r\n\r\n";
        error_defer(send(client_fd, resp_f, strlen(resp_f), 0));
    }
	log_fmt(LOG_KIND_INFO, "Response message sent");
defer:
    close(client_fd);
    log_fmt(LOG_KIND_INFO, "Connection closed");
    arena_free(&arena);
    return result;
}

int main() 
{
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    int server_fd = 0, result = 0;
    unsigned int client_addr_len;

	struct sockaddr_in client_addr;
	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd == -1)
    {
		log_fmt(LOG_KIND_ERROR, "Socket creation failed: %s...\n", strerror(errno));
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
    log_fmt(LOG_KIND_INFO, "Listening on port: 4221");

	client_addr_len = sizeof(client_addr);
    while(running)
    {
        log_fmt(LOG_KIND_INFO, "Waiting for a client to connect...\r");
        int client_fd;
        if((client_fd = accept(server_fd, (struct sockaddr *) &client_addr, &client_addr_len)) < 0)
        {
            log_fmt(LOG_KIND_WARNING, "Failed to accept connection: %s", strerror(errno));
            continue;
        }
        if(process_request(client_fd) < 0)
        {
            log_fmt(LOG_KIND_WARNING, "Failed to process connection");
        }
    }
    log_fmt(LOG_KIND_INFO, "Shutting down server");
defer:
    if(server_fd)
    {
        close(server_fd);
    }
	return result;
}
