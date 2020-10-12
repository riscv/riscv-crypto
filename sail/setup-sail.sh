#!/bin/bash

#
# A setup script for the SAIL ISA description language tool.
# Instructions here are based on:
# - https://github.com/rems-project/sail/blob/sail2/BUILDING.md
#

set -e  # Echo commands.
set -x  # Exit on first failed command.

#
# Standard packages
sudo add-apt-repository ppa:avsm/ppa # Comment out if running on Ubuntu 20:04 "Focal Fossa".
sudo apt-get update
sudo apt-get install build-essential git m4 libgmp-dev z3 opam

#
# Initialise OPAM
opam init

#
# Get the corect versions of OCaml
opam switch create ocaml-base-compiler.4.06.1
eval $(opam env)

#
# Install opam SAIL package
opam install sail

