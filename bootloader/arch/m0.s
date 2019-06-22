
        .thumb_func
        .type   invoke_pic, %function
        .global invoke_pic
invoke_pic:
        .fnstart
        .cantunwind

        ldr     r4, =0x20000ec4
        mov     r9, r4
        bx      r0

        .fnend
        .size   invoke_pic, .-invoke_pic
