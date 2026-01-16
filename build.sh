#!/usr/bin/env bash
set -xe
CC="gcc"
CFLAGS="-Wall -Wextra -Werror"
SRC="src/main.c"

mkdir -p build
$CC $CFLAGS $SRC -o build/http_server
