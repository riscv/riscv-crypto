#!/bin/bash

source $REPO_HOME/tools/common.sh

set -e
set -x

# ------ Binutils ----------------------------------------------------------

cd           $DIR_SPIKE
git apply    $REPO_HOME/tools/patch-spike.patch
git add      --all
