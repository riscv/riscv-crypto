#!/bin/bash

echo "------------- RISC-V Crypto Getting Started -----------------"

bash $REPO_HOME/tools/clone-repos.sh
bash $REPO_HOME/tools/apply-patch-all.sh
bash $REPO_HOME/tools/rebuild-all.sh

echo "---------- RISC-V Crypto Getting Started [DONE] -------------"

