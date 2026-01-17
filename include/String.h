#ifndef STRINGS_H
#define STRINGS_H

#define string_from_cstr(str) (String){ .data = str, .len = strlen(str), .capacity = strlen(str)}

typedef struct {
    char*  data;
    size_t len;
    size_t capacity;
} String;

char* string_to_cstr(Arena *arena, const String *s);
void display_string(String s);

#ifdef STRING_IMPLEMENTATION

char* string_to_cstr(Arena *arena, const String *s)
{
    size_t capacity = (sizeof(char) * s->len) + 1;
    char* buffer = arena_alloc(arena, capacity);
    *(char*)mempcpy(buffer, s->data, s->len) = '\0';
    return buffer;
}

void string_concat_cstr(Arena *arena, String *s, const char* cstr)
{
    size_t cstr_len = strlen(cstr);
    if(s->len + cstr_len > s->capacity)
    {
        size_t new_capacity =  s->capacity ? (s->capacity * 2 ) + cstr_len : cstr_len;
        char* new_pointer = arena_realloc(arena, s->data, s->capacity, new_capacity);
        s->data = new_pointer;
        s->capacity = new_capacity;
    }
    memcpy(s->data + s->len, cstr, cstr_len);
    s->len += cstr_len;
}

void display_string(String s)
{
    printf("(String) { \n    .data = %s, \n    .len = %zu, \n    capacity = %zu\n }\n",
            s.data, s.len, s.capacity);
}

#endif
#endif //STRINGS_H
