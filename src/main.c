#include <stdio.h>
#include <pthread.h>
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

char* read_file(Arena* arena, const char* filepath)
{
    char* buffer = NULL;
    int result = 1;
    FILE *file = fopen(filepath, "rb");
    if(!file)
    {
        log_fmt(LOG_KIND_ERROR, "could not open %s: %s", filepath, strerror(errno));
        result = 0;
        goto defer;
    }
    if(fseek(file, 0, SEEK_END) < 0)
    {
        log_fmt(LOG_KIND_ERROR, "could not seek_end %s: %s", filepath, strerror(errno));
        result = 0;
        goto defer;
    }
    size_t file_size = ftell(file);
    if(fseek(file, 0, SEEK_SET) < 0)
    {
        log_fmt(LOG_KIND_ERROR, "could not seek_set %s: %s\n", filepath, strerror(errno));
        result = 0;
        goto defer;
    }
    buffer = arena_alloc(arena, (sizeof(char) * file_size) + 1);
    size_t read_bytes = fread(buffer, sizeof(char), file_size, file);
    if(read_bytes < file_size)
    {
        log_fmt(LOG_KIND_ERROR, "could not read bytes %s", filepath);
        result = 0;
        goto defer;
    }
    *(buffer+file_size) = '\0';
defer:
    if(file)
    {
        fclose(file);
    }
    return result ? assert(buffer), buffer : NULL;
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
           log_fmt(LOG_KIND_ERROR,__FILE__ ":%d:" #func " %s", __LINE__, strerror(errno));     \
           result = -1;                                                                        \
           goto defer;                                                                         \
       }                                                                                       \
    }                                                                                          \
    while(0)
#define assert_non_null(expr)                                                                         \
    do                                                                                                \
    {                                                                                                 \
        if((expr) == NULL)                                                                            \
        {                                                                                             \
           log_fmt(LOG_KIND_ERROR,__FILE__ ":%d:" #expr " is expected to be not null", __LINE__);     \
           result = -1;                                                                               \
           goto defer;                                                                                \
        }                                                                                             \
    }                                                                                                 \
    while(0)

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

typedef enum
{
    RES_OK = 200,
    RES_NOT_FOUND = 404,
} RES_STATUS;

typedef struct
{
    Header* headers;
    char* version;
    char* body;
    RES_STATUS status;
} Response;

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

int create_response(Arena *arena, Response *response, const Request* request)
{
    int result = 0;
    assert_non_null(request->target);
    response->version =  "HTTP/1.1 ";
    response->headers = hm_init(arena);
    if(strcmp(request->target, "/") == 0)
    {
        response->status = RES_OK;
        char* homepage = read_file(arena, "assets/index.html");
        hm_insert(response->headers, (Header) {"Content-Type", "text/html"});
        char* content_len = arena_sprintf(arena, "%zu", strlen(homepage));
        hm_insert(response->headers, (Header) {"Content-Length", content_len});
        response->body = homepage;
    }
    else if(strncmp(request->target, "/echo/", 6) == 0)
    {
        //NOTE: discard the request->target because we already hit the endpoint
        (void)strtok(request->target, "/");
        char* echo_message = strtok(NULL, "/");
        if(!echo_message) echo_message = "";
        response->status = RES_OK;
        hm_insert(response->headers, (Header) {"Content-Type", "text/plain"});
        char* content_len = arena_sprintf(arena, "%zu", strlen(echo_message));
        hm_insert(response->headers, (Header) {"Content-Length", content_len});
        response->body = echo_message;
    }
    else if(strncmp(request->target, "/user-agent", 11) == 0)
    {
        Header* user_agent = hm_get(request->headers, "user-agent");
        assert_non_null(user_agent);
        response->status = RES_OK;
        hm_insert(response->headers, (Header) {"Content-Type", "text/plain"});
        char* content_len = arena_sprintf(arena, "%zu", strlen(user_agent->value));
        hm_insert(response->headers, (Header) {"Content-Length", content_len});
        response->body = user_agent->value;
    }
    else
    {
        response->status  = RES_NOT_FOUND;
        response->headers = NULL;
        response->body    = NULL;
        log_fmt(LOG_KIND_ERROR, "request->target %s not found", request->target);
    }
defer:
    return result;
}

int send_response(Arena* arena, const int client_fd,  const Response *res)
{
    int result = 0;
    String res_msg = {0};
    string_concat_cstr(arena, &res_msg, res->version);
    switch(res->status)
    {
        case RES_OK: 
            string_concat_cstr(arena, &res_msg, "200 OK");
            break;
        case RES_NOT_FOUND: 
            string_concat_cstr(arena, &res_msg, "404 Not Found");
            break;
    }
    string_concat_cstr(arena, &res_msg, "\r\n");
    if(res->headers != NULL)
    {
        for(size_t i = 0; i < HEADER_TABLE_MAX; i++)
        {
            Header h = res->headers[i];
            if(h.key == NULL) continue;
            char* content_type = arena_sprintf(arena, "%s: %s\r\n", h.key, h.value);
            string_concat_cstr(arena, &res_msg, content_type);
        }
    }
    string_concat_cstr(arena, &res_msg, "\r\n");
    if(res->body != NULL)
    {
        string_concat_cstr(arena, &res_msg, res->body);
    }
    char* resp = string_to_cstr(arena, &res_msg);
    error_defer(send(client_fd, resp, strlen(resp), 0));
defer:
    return result;
}

void* process_request(void* arg)
{
	log_fmt(LOG_KIND_INFO, "Client connected");
    const int client_fd = *(int*)arg;
    Arena arena = {0};
    int result = 0;
    char buffer[1024] = {0};
    error_defer(recv(client_fd, buffer, sizeof(buffer), 0));

    Request request = {0};
    error_defer(parse_request(&arena, &request, buffer));

    Response response = {0};
    error_defer(create_response(&arena, &response, &request));

    error_defer(send_response(&arena, client_fd, &response));
	log_fmt(LOG_KIND_INFO, "Response message sent");
defer:
    close(client_fd);
    free((int*)arg);
    log_fmt(LOG_KIND_INFO, "Connection closed");
    arena_free(&arena);
    //TODO: figure out what to do with the result
    (void)result;
    return NULL;
}

int main() 
{
    setbuf(stdout, NULL);
 	setbuf(stderr, NULL);
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
        //TODO: implement a thread pool or event loop
        int *new_sock = malloc(sizeof(int));
        assert_non_null(new_sock);
        *new_sock = client_fd;
        pthread_t thread;
        pthread_create(&thread, NULL, process_request, new_sock);
        pthread_detach(thread);
    }
    log_fmt(LOG_KIND_INFO, "Shutting down server");
defer:
    if(server_fd)
    {
        close(server_fd);
    }
	return result;
}
