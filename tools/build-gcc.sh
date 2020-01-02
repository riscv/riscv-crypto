#!/bin/bash

source $REPO_HOME/tools/common.sh

set -e
set -x

export RISCV=$INSTALL_DIR

mkdir -p $INSTALL_DIR

# ------ GCC ---------------------------------------------------------------

cd   $DIR_GCC_BUILD

make -j$(nproc)
make install

