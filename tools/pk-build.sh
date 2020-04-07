#!/bin/bash

source $REPO_HOME/tools/share.sh

set -e
set -x

export RISCV=$INSTALL_DIR

mkdir -p $INSTALL_DIR

# ------ Proxy Kernel (PK) 32-bit-------------------------------------------

export PATH="$RISCV/bin:$PATH"

cd           $DIR_PK32_BUILD

make
make install

cd           $DIR_PK64_BUILD

make
make install
