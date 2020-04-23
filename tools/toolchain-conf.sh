#!/bin/bash

source $REPO_HOME/tools/share.sh

set -e
set -x

export RISCV=$INSTALL_DIR

mkdir -p $INSTALL_DIR

# ------ Spike -------------------------------------------------------------

refresh_dir  $DIR_TOOLCHAIN_BUILD
cd           $DIR_TOOLCHAIN_BUILD
$DIR_TOOLCHAIN/configure \
    --prefix=$INSTALL_DIR \
    --enable-multilib \
    --disable-gdb


