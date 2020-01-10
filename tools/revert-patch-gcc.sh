#!/bin/bash

source $REPO_HOME/tools/common.sh

set -e
set -x

# ------ Spike -------------------------------------------------------------

#
# This script reverts all XCrypto related changes to Spike.
#

cd           $DIR_GCC
git reset HEAD
git checkout .
git clean -df


