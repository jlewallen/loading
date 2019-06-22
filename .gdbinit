add-symbol-file build/m0-fk/bootloader/bootloader.elf 0x0000

target extended-remote :2331
load
b Dummy_Handler
b cm_shim_hard_fault
b cm_shim_nmi
b cm_shim_pendsv
b cm_shim_svc
b try_launch
b invoke_pic
monitor reset
continue
