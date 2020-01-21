#!/bin/bash

source $REPO_HOME/tools/share.sh

set -e
set -x

# ------ GCC ---------------------------------------------------------------

cd           $DIR_GCC
git apply    $PATCH_GCC
git add      --all

