
        .thumb_func
        .type   invoke_pic, %function
        .global invoke_pic
invoke_pic:
        .fnstart
        .cantunwind

        msr     MSP, r0
        mov     r9, r2
        bx      r1

        .fnend
        .size   invoke_pic, .-invoke_pic
