
.text

.extern main

.global _start
_start:
    la sp, _stack_end
    j main


.balign 8
.global tohost 
tohost:
    

.balign 16
_stack:
.balign 512
_stack_end:
