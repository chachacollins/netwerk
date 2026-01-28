#!/usr/bin/env bash
CC="gcc"
CFLAGS="-Wall -Wextra -Werror -ggdb"
SRC="src/main.c"
if [ "$1" == "dev" ]; then
    D="-DDEV"
else
    D="-DLOCAL"
fi

set -xe

mkdir -p build
$CC $D -Iinclude $CFLAGS $SRC -o build/http_server -lpthread
