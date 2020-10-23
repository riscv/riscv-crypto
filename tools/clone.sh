#!/bin/bash

source $REPO_HOME/tools/share.sh

set -e
set -x

# ------ Toolchain ----------------------------------------------------------

cd $REPO_HOME
git submodule update --init extern/riscv-gnu-toolchain

cd $DIR_TOOLCHAIN
git submodule update --init --recursive riscv-binutils
git submodule update --init --recursive riscv-dejagnu
git submodule update --init --recursive riscv-gcc
git submodule update --init --recursive riscv-gdb
git submodule update --init --recursive riscv-glibc
git submodule update --init --recursive riscv-newlib

cd $DIR_GCC
git checkout riscv-bitmanip
git checkout $GCC_COMMIT

cd $DIR_BINUTILS
git checkout riscv-bitmanip
git checkout $BINUTILS_COMMIT

# ------ Proxy Kernel (PK) -------------------------------------------------

if [ ! -d $DIR_PK ]; then
    git clone https://github.com/riscv/riscv-pk.git $DIR_PK
fi

cd $DIR_PK
git checkout -B $BRANCH_NAME

# ------ SPIKE ISA Simulator -----------------------------------------------

cd $REPO_HOME
git submodule update --init --recursive extern/riscv-isa-sim

cd $DIR_SPIKE
git checkout $SPIKE_COMMIT

# --------------------------------------------------------------------------

cd $REPO_HOME

