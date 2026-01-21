#!/usr/bin/env bash
CC="gcc"
CFLAGS="-Wall -Wextra -Werror -ggdb"
SRC="src/main.c"

set -xe

mkdir -p build
$CC -Iinclude $CFLAGS $SRC -o build/http_server -lpthread
