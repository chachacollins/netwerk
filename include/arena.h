#ifndef ARENA_H
//based on TSODING's arena implementation
#define ARENA_H
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARENA_DEFAULT_SIZE (1024*8)

typedef struct Region Region;

struct Region {
    Region* next;
    size_t capacity;
    size_t count;
    uintptr_t data[];
};

typedef struct {
    Region *start, *end;
} Arena;

typedef struct {
    Region *ptr;
    size_t count;
} Arena_Mark;

void* arena_alloc(Arena *arena, size_t size);
void *arena_realloc(Arena *a, void *oldptr, size_t oldsz, size_t newsz);
void  arena_free(Arena *arena);
void  arena_reset(Arena *arena);
#define arena_set_mark(a) ((Arena_Mark) {.ptr = (a)->end, .count = (a)->end->count})
void arena_restore_mark(Arena *arena, Arena_Mark mark);
void  arena_display(Arena *arena);

#ifdef ARENA_IMPLEMENTATION
Region* new_region(size_t size)
{
    Region* region = malloc(sizeof(Region) + sizeof(uintptr_t) * size);
    assert(region);
    region->capacity = size;
    region->count = 0;
    region->next = NULL;
    return region;
}

void free_region(Region *r)
{
    free(r);
}

void* arena_alloc(Arena *arena, size_t size_r)
{
    size_t size = (size_r + sizeof(uintptr_t) - 1) / sizeof(uintptr_t);
    if(arena->end == NULL)
    {
       assert(arena->start == NULL);
       size_t capacity = ARENA_DEFAULT_SIZE;
       if(capacity < size) capacity = size;
       arena->end = new_region(capacity);
       arena->start = arena->end;
    }
    while(arena->end->count + size > arena->end->capacity && arena->end->next != NULL)
    {
        arena->end = arena->end->next;
    }
    if(arena->end->count + size > arena->end->capacity)
    {
        assert(arena->end->next == NULL);
        size_t capacity = ARENA_DEFAULT_SIZE;
        if(capacity < size) capacity = size;
        arena->end->next = new_region(capacity);
        arena->end = arena->end->next;
    }
    void* data = &arena->end->data[arena->end->count];
    arena->end->count += size;
    return data;
}

void *arena_realloc(Arena *arena, void *oldptr, size_t oldsz, size_t newsz)
{
    if (newsz <= oldsz) return oldptr;
    void* newptr = arena_alloc(arena, newsz);
    memcpy(newptr, oldptr, oldsz);
    return newptr;
}

void arena_reset(Arena *arena)
{
    Region *current = arena->start;
    while(current != NULL)
    {
        current->count = 0;
        current = current->next;
    }
    arena->end = arena->start;
}

void arena_free(Arena *arena)
{
    Region *p;
    while(arena->start)
    {
        p = arena->start;
        arena->start = arena->start->next;
        free_region(p);
    }
    arena->start = NULL;
    arena->end = NULL;
}

void arena_restore_mark(Arena *arena, Arena_Mark mark)
{
    assert(mark.ptr);
    assert(arena);
    for(Region *p = mark.ptr->next; p != NULL; p = p->next)
    {
        p->count = 0;
    }
    arena->end = mark.ptr;
    arena->end->count = mark.count;
}

void print_region(Region* r)
{
    printf("----------Begin region(%p) ----------\n", (void*)r->data);
    printf("capacity = %zu\n", r->capacity);
    printf("count    = %zu\n", r->count);
    printf("----------End   region ----------\n");
}

void arena_display(Arena *arena)
{
    printf("---------- Arena Allocations ----------\n");
    for(Region* p = arena->start; p != NULL; p = p->next)
    {
        print_region(p);
    }
}

#endif //ARENA_IMPLEMENTATION
#endif //ARENA_H
