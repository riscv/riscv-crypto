#!/bin/bash

source $REPO_HOME/tools/common.sh

set -e
set -x

export RISCV=$INSTALL_DIR

mkdir -p $INSTALL_DIR

# ------ GCC ---------------------------------------------------------------

refresh_dir  $DIR_GCC_BUILD
cd           $DIR_GCC_BUILD
$DIR_GCC/configure \
    --prefix=$INSTALL_DIR \
    --enable-languages=c \
    --disable-libssp \
    --target=$TARGET_ARCH \
    --enable-multilib

