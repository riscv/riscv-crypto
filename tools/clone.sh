#!/bin/bash

source $REPO_HOME/tools/share.sh

set -e
set -x

# ------ Binutils ----------------------------------------------------------

if [ ! -d $DIR_BINUTILS ]; then
    git clone https://github.com/riscv/riscv-binutils-gdb.git $DIR_BINUTILS
fi

cd $DIR_BINUTILS
git checkout -B $BRANCH_NAME $COMMIT_BINUTILS # riscv-bitmanip
cd -

# ------ GCC ---------------------------------------------------------------

if [ ! -d $DIR_GCC ]; then
    git clone https://github.com/riscv/riscv-gcc.git $DIR_GCC
fi

cd $DIR_GCC
git checkout -B $BRANCH_NAME $COMMIT_GCC # riscv-bitmanip
./contrib/download_prerequisites
cd -

# ------ NewLib ------------------------------------------------------------

if [ ! -d $DIR_NEWLIB ]; then
    git clone https://github.com/riscv/riscv-newlib.git $DIR_NEWLIB
fi

cd $DIR_NEWLIB
git checkout -B $BRANCH_NAME riscv-newlib-3.1.0
cd -

# ------ Proxy Kernel (PK) -------------------------------------------------

if [ ! -d $DIR_PK ]; then
    git clone https://github.com/riscv/riscv-pk.git $DIR_PK
fi

cd $DIR_PK
git checkout -B $BRANCH_NAME
cd -

# ------ SPIKE ISA Simulator -----------------------------------------------

if [ ! -d $DIR_SPIKE ]; then
    git clone https://github.com/riscv/riscv-isa-sim.git $DIR_SPIKE
fi

cd $DIR_SPIKE
git checkout -B $BRANCH_NAME $COMMIT_SPIKE # riscv-bitmanip
cd -

# --------------------------------------------------------------------------

