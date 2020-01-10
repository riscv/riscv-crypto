#!/bin/bash

source $REPO_HOME/tools/common.sh

set -e
set -x

# ------ GCC ---------------------------------------------------------------

#
# This script reverts all Crypto related changes to binutils.
#

cd           $DIR_GCC
git reset HEAD
git checkout .
git clean -df

