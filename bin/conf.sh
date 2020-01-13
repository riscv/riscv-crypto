#!/bin/bash

export REPO_HOME="${PWD}"
export REPO_BUILD=$REPO_HOME/build
export RISCV=$REPO_BUILD/toolchain/install

echo "---- Setting Up Workspace ----"

if [ ! -d "$REPO_BUILD" ]; then
    mkdir -p $REPO_BUILD
    echo "Created \$REPO_BUILD directory."
else
    echo "REPO_BUILD directory already exists."
fi

if [ -z $YOSYS_ROOT ] ; then
    # Export a dummy "Yosys Root" path environment variable.
    export YOSYS_ROOT=/usr/bin
    echo "YOSYS_ROOT is empty. Setting to '$YOSYS_ROOT'"
fi


echo "REPO_HOME  = $REPO_HOME"
echo "REPO_BUILD = $REPO_BUILD"
echo "RISCV      = $RISCV"
echo "YOSYS_ROOT = $YOSYS_ROOT"

echo "------------------------------"

