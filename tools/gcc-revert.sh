#!/bin/bash

source $REPO_HOME/tools/share.sh

set -e
set -x

# ------ Binutils ----------------------------------------------------------

#
# This script reverts all XCrypto related changes to binutils.
#

cd           $DIR_GCC
git reset HEAD
git checkout .
git clean -df

