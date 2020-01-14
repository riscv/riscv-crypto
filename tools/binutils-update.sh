#!/bin/bash

source $REPO_HOME/tools/share.sh

set -e
set -x

# ------ Binutils ----------------------------------------------------------

cd           $DIR_BINUTILS
git diff --cached > $PATCH_BINUTILS


