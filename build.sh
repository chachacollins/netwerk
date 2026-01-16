#!/usr/bin/env bash
CC="gcc"
CFLAGS="-Wall -Wextra -Werror"
SRC="src/main.c"

set -xe

mkdir -p build
$CC $CFLAGS $SRC -o build/http_server
