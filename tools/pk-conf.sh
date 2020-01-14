#!/bin/bash

source $REPO_HOME/tools/share.sh

set -e
set -x

export RISCV=$INSTALL_DIR

mkdir -p $INSTALL_DIR

# ------ Proxy Kernel (PK) 32-bit-------------------------------------------

refresh_dir  $DIR_PK32_BUILD
cd           $DIR_PK32_BUILD

export PATH="$RISCV/bin:$PATH"

$DIR_PK/configure \
    --prefix=$INSTALL_DIR \
    --host=riscv64-unknown-elf \
    --with-abi=ilp32 --with-arch=rv32ic

# ------ Proxy Kernel (PK) 64-bit-------------------------------------------

refresh_dir  $DIR_PK64_BUILD
cd           $DIR_PK64_BUILD

export PATH="$RISCV/bin:$PATH"

$DIR_PK/configure \
    --prefix=$INSTALL_DIR \
    --host=riscv64-unknown-elf

