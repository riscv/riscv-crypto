#!/bin/bash

source $REPO_HOME/tools/share.sh

set -e
set -x

export RISCV=$INSTALL_DIR

mkdir -p $INSTALL_DIR

# ------ Toolchain -------------------------------------------------------------

cd           $DIR_TOOLCHAIN_BUILD

make  -j 4
make install

