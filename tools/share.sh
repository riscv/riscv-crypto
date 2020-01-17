
DIR_BASE=$REPO_BUILD/toolchain

DIR_GCC=$DIR_BASE/riscv-gcc
DIR_BINUTILS=$DIR_BASE/riscv-binutils
DIR_NEWLIB=$DIR_BASE/riscv-newlib
DIR_PK=$DIR_BASE/riscv-pk
DIR_SPIKE=$DIR_BASE/riscv-isa-sim

DIR_GCC_BUILD=$DIR_GCC-$RISCV_ARCH
DIR_BINUTILS_BUILD=$DIR_BINUTILS-$RISCV_ARCH
DIR_NEWLIB_BUILD=$DIR_NEWLIB-$RISCV_ARCH
DIR_PK_BUILD=$DIR_PK-$RISCV_ARCH
DIR_SPIKE_BUILD=$DIR_SPIKE-$RISCV_ARCH

BRANCH_NAME=riscv-crypto

INSTALL_DIR=$RISCV
TARGET_ARCH=$RISCV_ARCH

#
# Known good git commit hashes to apply patches too
COMMIT_GCC=7aad2f362811fb07d75eea90aaebd16fca714d4c
COMMIT_BINUTILS=c870418800cd390bb2ae531226efd8a8ce1b741d
COMMIT_SPIKE=5b042d731458eafea538324e2bf4f1d44ce9d2a0

#
# Patch files
PATCH_BINUTILS=$REPO_HOME/tools/patch-binutils.patch
PATCH_GCC=$REPO_HOME/tools/patch-gcc.patch
PATCH_NEWLIB=$REPO_HOME/tools/patch-newlib.patch
PATCH_SPIKE=$REPO_HOME/tools/patch-spike.patch
PATCH_PK=$REPO_HOME/tools/patch-pk.patch

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
