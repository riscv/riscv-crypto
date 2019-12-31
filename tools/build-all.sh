#!/bin/bash

set -e
set -x

bash $REPO_HOME/tools/build-binutils.sh
bash $REPO_HOME/tools/build-gcc.sh
bash $REPO_HOME/tools/build-newlib.sh
bash $REPO_HOME/tools/build-pk.sh
bash $REPO_HOME/tools/build-spike.sh

