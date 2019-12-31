#!/bin/bash

source $REPO_HOME/tools/common.sh

set -e
set -x

export RISCV=$INSTALL_DIR

mkdir -p $INSTALL_DIR

# ------ Spike -------------------------------------------------------------

refresh_dir  $DIR_SPIKE_BUILD
cd           $DIR_SPIKE_BUILD
$DIR_SPIKE/configure \
    --prefix=$INSTALL_DIR \
    --target=$TARGET_ARCH

make -j 2
make install

