#!/bin/bash

source $REPO_HOME/tools/share.sh

set -e
set -x

# ------ Binutils ----------------------------------------------------------

cd           $DIR_BINUTILS
git apply    $PATCH_BINUTILS
git add      --all

