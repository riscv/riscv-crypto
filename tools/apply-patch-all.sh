#!/bin/bash

set -e
set -x

bash $REPO_HOME/tools/apply-patch-binutils.sh
bash $REPO_HOME/tools/apply-patch-gcc.sh
