#!/bin/bash

source $REPO_HOME/tools/common.sh

set -e
set -x

# ------ Spike -------------------------------------------------------------

cd           $DIR_GCC
git diff --cached > $PATCH_GCC

