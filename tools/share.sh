
DIR_TOOLCHAIN=$REPO_HOME/extern/riscv-gnu-toolchain
DIR_GCC=$DIR_TOOLCHAIN/riscv-gcc
DIR_BINUTILS=$DIR_TOOLCHAIN/riscv-binutils
DIR_NEWLIB=$DIR_TOOLCHAIN/riscv-newlib
DIR_PK=$REPO_BUILD/riscv-pk
DIR_SPIKE=$REPO_HOME/extern/riscv-isa-sim

DIR_TOOLCHAIN_BUILD=$REPO_BUILD/toolchain
DIR_PK32_BUILD=$DIR_PK-riscv32-unknown-elf
DIR_PK64_BUILD=$DIR_PK-riscv64-unknown-elf
DIR_SPIKE_BUILD=$REPO_BUILD/riscv-isa-sim

BRANCH_NAME=riscv-crypto

INSTALL_DIR=$RISCV
TARGET_ARCH=$RISCV_ARCH

#
# Patch files
PATCH_BINUTILS=$REPO_HOME/tools/patch-binutils.patch
PATCH_SPIKE=$REPO_HOME/tools/patch-spike.patch

#
# Known good commits
SPIKE_COMMIT=3d19864f39ac525162896ae5025f44834f91c83c
BINUTILS_COMMIT=c870418800cd390bb2ae531226efd8a8ce1b741d
GCC_COMMIT=7aad2f362811fb07d75eea90aaebd16fca714d4c

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
