#ifndef PRINT_H
#define PRINT_H
#ifdef PRINT_IMPLEMENTATION
#define print(X) _Generic((X),                          \
    char: print_char,                                   \
    signed char: print_signed_char,                     \
    unsigned char: print_unsigned_char,                 \
    short: print_short,                                 \
    unsigned short: print_unsigned_short,               \
    int: print_int,                                     \
    unsigned int: print_unsigned_int,                   \
    long: print_long,                                   \
    long long: print_long_long,                         \
    unsigned long long: print_unsigned_long_long,       \
    float: print_float,                                 \
    double: print_double,                               \
    long double: print_long_double,                     \
    bool: print_bool,                                   \
    char*: print_cstr,                                  \
    const char*: print_cstr,                            \
    void*: print_pointer,                               \
    size_t: print_size_t,                               \
    String: print_string                                \
    )(X)


void print_string(String s)
{
    printf("%.*s", (int)s.len, s.data);
}

void print_char(char c)
{
    printf("%c", c);
}

void print_signed_char(signed char c)
{
    printf("%hhd", c);
}

void print_unsigned_char(unsigned char c)
{
    printf("%hhu", c);
}

void print_short(short n)
{
    printf("%hd", n);
}

void print_unsigned_short(unsigned short n) 
{
    printf("%hu", n);
}

void print_int(int n)
{
    printf("%d", n);
}

void print_unsigned_int(unsigned int n)
{
    printf("%u", n);
}

void print_long(long n)
{
    printf("%ld", n);
}

void print_unsigned_long(unsigned long n)
{
    printf("%lu", n);
}

void print_long_long(long long n)
{
    printf("%lld", n);
}

void print_unsigned_long_long(unsigned long long n)
{
    printf("%llu", n);
}

void print_float(float f)
{
    printf("%f", f);
}

void print_double(double d)
{
    printf("%lf", d);
}

void print_long_double(long double ld)
{
    printf("%Lf", ld);
}

void print_bool(bool b)
{
    printf("%s", b ? "true" : "false");
}

void print_pointer(void *ptr)
{
    printf("%p", ptr);
}

void print_size_t(size_t n)
{
    printf("%zu", n);
}

void print_cstr(const char *str)
{
    printf("%s", str);
}
#endif
#endif //PRINT_H
