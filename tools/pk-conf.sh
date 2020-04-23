#!/bin/bash

source $REPO_HOME/tools/share.sh

set -e
set -x

export RISCV=$INSTALL_DIR

mkdir -p $INSTALL_DIR

# ------ Proxy Kernel (PK) 32-bit-------------------------------------------

export PATH="$RISCV/bin:$PATH"

refresh_dir  $DIR_PK32_BUILD
cd           $DIR_PK32_BUILD

$DIR_PK/configure \
    --prefix=$INSTALL_DIR \
    --host=$TARGET_ARCH --with-arch=rv32imac \


refresh_dir  $DIR_PK64_BUILD
cd           $DIR_PK64_BUILD

$DIR_PK/configure \
    --prefix=$INSTALL_DIR \
    --host=$TARGET_ARCH \
