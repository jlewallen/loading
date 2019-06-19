# source ~/tools/bin/micro-trace-buffer.py

add-symbol-file build/m0-fk/blink/blink-reg.elf 0x4000

target extended-remote :2331
load
b cm_shim_hard_fault
b cm_shim_nmi
b cm_shim_pendsv
b cm_shim_svc
monitor reset
continue
