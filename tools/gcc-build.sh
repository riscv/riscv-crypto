#!/bin/bash

source $REPO_HOME/tools/share.sh

set -e
set -x

export RISCV=$INSTALL_DIR

mkdir -p $INSTALL_DIR

# ------ GCC ---------------------------------------------------------------

cd   $DIR_GCC_BUILD

make -j 4 
make install

