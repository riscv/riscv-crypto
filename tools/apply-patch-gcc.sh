#!/bin/bash

source $REPO_HOME/tools/common.sh

set -e
set -x

# ------ Binutils ----------------------------------------------------------

cd           $DIR_GCC
git apply    $REPO_HOME/tools/patch-gcc.patch
git add      --all
