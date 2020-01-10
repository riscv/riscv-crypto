#!/bin/bash

source $REPO_HOME/tools/common.sh

set -e
set -x

# ------ Binutils ----------------------------------------------------------

#
# This script reverts all XCrypto related changes to binutils.
#

cd           $DIR_BINUTILS
git reset HEAD
git checkout .
git clean -df


