#!/bin/bash

source $REPO_HOME/tools/common.sh

set -e
set -x

# ------ Binutils ----------------------------------------------------------

cd           $DIR_BINUTILS
git apply    $REPO_HOME/tools/patch-binutils.patch

