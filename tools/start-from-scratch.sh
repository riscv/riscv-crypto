#!/bin/bash

source $REPO_HOME/tools/share.sh

echo "Setting up toolchain..."
echo "---------------------------------------------------"
echo "Download Dir    : $DIR_BASE"
echo "Installation Dir: $INSTALL_DIR"
echo "Target Arch     : $TARGET_ARCH"
echo "GCC Commit      : $GCC_COMMIT"
echo "Binutils Commit : $BINUTILS_COMMIT"
echo ""
echo "DIR_GCC         = $DIR_GCC"
echo "DIR_BINUTILS    = $DIR_BINUTILS"
echo "DIR_NEWLIB      = $DIR_NEWLIB"
echo "DIR_PK          = $DIR_PK"
echo "DIR_SPIKE       = $DIR_SPIKE"
echo ""
echo "Branch Name     = $BRANCH_NAME"
echo "---------------------------------------------------"

set -e
set -x

bash $REPO_HOME/tools/clone.sh

bash $REPO_HOME/tools/binutils-apply.sh

bash $REPO_HOME/tools/toolchain-conf.sh
bash $REPO_HOME/tools/spike-conf.sh

bash $REPO_HOME/tools/toolchain-build.sh
bash $REPO_HOME/tools/spike-build.sh

bash $REPO_HOME/tools/pk-conf.sh
bash $REPO_HOME/tools/pk-build.sh

