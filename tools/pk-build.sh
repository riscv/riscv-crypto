#!/bin/bash

source $REPO_HOME/tools/share.sh

set -e
set -x

export RISCV=$INSTALL_DIR

mkdir -p $INSTALL_DIR

# ------ Proxy Kernel (PK) 32-bit-------------------------------------------

cd           $DIR_PK_BUILD

export PATH="$RISCV/bin:$PATH"

make
make install

