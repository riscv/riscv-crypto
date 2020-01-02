
#
# This file doesn't actually assemble any code, it just checks that
# we can properly specify the arch strings for Scalar crypto on
# the command line.
# Specifically, it checks we can *compile* a minimal assembly code program.

.text

.global main
main:
    li a0, 0
    ret
