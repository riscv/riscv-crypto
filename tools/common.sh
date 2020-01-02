
DIR_BASE=$REPO_BUILD/toolchain

DIR_GCC=$DIR_BASE/riscv-gcc
DIR_BINUTILS=$DIR_BASE/riscv-binutils
DIR_NEWLIB=$DIR_BASE/riscv-newlib
DIR_PK=$DIR_BASE/riscv-pk
DIR_SPIKE=$DIR_BASE/riscv-isa-sim

DIR_GCC_BUILD=$DIR_GCC-build
DIR_BINUTILS_BUILD=$DIR_BINUTILS-build
DIR_NEWLIB_BUILD=$DIR_NEWLIB-build
DIR_PK_BUILD=$DIR_PK-build
DIR_SPIKE_BUILD=$DIR_SPIKE-build

BRANCH_NAME=riscv-crypto

INSTALL_DIR=$REPO_BUILD/toolchain/install
TARGET_ARCH=riscv32-unknown-elf
ARCH_STRING=rv32imacb_zscrypto
ABI_STRING=ilp32

#
# Check that a directory exists and exit if not.
#
function check_dir {
if [ ! -d $1 ]; then
    echo "$1 does not exist." ; exit 1
fi
}

#
# Check if the directory exists. If so, delete it and create fresh.
#
function refresh_dir {
if [ -d $1 ]; then
    rm -rf $1
fi
mkdir -p $1
}
