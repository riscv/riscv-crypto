#!/bin/bash

set -e
set -x

bash $REPO_HOME/tools/binutils-conf.sh
bash $REPO_HOME/tools/binutils-build.sh
bash $REPO_HOME/tools/gcc-conf.sh
bash $REPO_HOME/tools/gcc-build.sh
bash $REPO_HOME/tools/newlib-conf.sh
bash $REPO_HOME/tools/newlib-build.sh
bash $REPO_HOME/tools/pk-conf.sh
bash $REPO_HOME/tools/pk-build.sh
bash $REPO_HOME/tools/spike-conf.sh
bash $REPO_HOME/tools/spike-build.sh
