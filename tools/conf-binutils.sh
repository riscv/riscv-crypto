#!/bin/bash

source $REPO_HOME/tools/common.sh

set -e
set -x

export RISCV=$INSTALL_DIR

mkdir -p $INSTALL_DIR

# ------ Binutils ----------------------------------------------------------

refresh_dir  $DIR_BINUTILS_BUILD
cd           $DIR_BINUTILS_BUILD
$DIR_BINUTILS/configure \
    --prefix=$INSTALL_DIR \
    --target=$TARGET_ARCH \
    --enable-multilib

