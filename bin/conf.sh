#!/bin/bash

export REPO_HOME="${PWD}"
export REPO_BUILD=$REPO_HOME/build

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


if [ -z $RISCV_ARCH ] ; then
    export RISCV_ARCH=riscv64-unknown-elf
fi

export RISCV=$REPO_BUILD/$RISCV_ARCH
export SAIL_RISCV=$REPO_HOME/extern/sail-riscv

[[ ":$PATH:" != *":$RISCV/bin:"* ]] && export PATH="${RISCV}/bin:${PATH}"
[[ ":$PATH:" != *":$SAIL_RISCV/c_emulator:"* ]] && export PATH="$SAIL_RISCV/c_emulator:${PATH}"
[[ ":$PATH:" != *":$SAIL_RISCV/ocaml_emulator:"* ]] && export PATH="$SAIL_RISCV/ocaml_emulator:${PATH}"

echo "REPO_HOME  = $REPO_HOME"
echo "REPO_BUILD = $REPO_BUILD"
echo "RISCV_ARCH = $RISCV_ARCH"
echo "RISCV      = $RISCV"
echo "YOSYS_ROOT = $YOSYS_ROOT"
echo "SAIL_RISCV = $SAIL_RISCV"
echo "PATH       = $PATH"

echo "------------------------------"

