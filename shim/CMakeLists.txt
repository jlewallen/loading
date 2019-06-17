set(CMAKE_C_COMPILER arm-none-eabi-gcc)
set(CMAKE_C_COMPILER arm-none-eabi-gcc)

add_library(shim SHARED shim.c)

if(TARGET_M4)
  set(target_mcu "cortex-m4")
  set(target_fcpu "120000000L")
  set(target_board_flags -DF_CPU=${target_fcpu} -D__SAMD51__ -D__FPU_PRESENT -DARM_MATH_CM4 -mfloat-abi=hard -mfpu=fpv4-sp-d16)
  set(target_c_flags -Os -s -ffunction-sections -fdata-sections -nostdlib --param max-inline-insns-single=500 -MMD -mcpu=${target_mcu} -mthumb ${target_board_flags} -fstack-usage) # -fno-threadsafe-statics -fno-rtti -fno-exceptions)
  set(linker_script ${CMAKE_SOURCE_DIR}/linking/samd51x19_bootloader_small.ld)
endif()

if(TARGET_M0)
  set(target_mcu "cortex-m0plus")
  set(target_fcpu "48000000l")
  set(target_board_flags -DF_CPU=${target_fcpu} -D__SAMD21__ -D__SAMD21G18A__ -DARM_MATH_CM0PLUS)
  set(target_c_flags -Os -s -ffunction-sections -fdata-sections -nostdlib --param max-inline-insns-single=500 -MMD -mcpu=${target_mcu} -mthumb ${target_board_flags} -fstack-usage) # -fno-threadsafe-statics -fno-rtti -fno-exceptions)
  set(linker_script ${CMAKE_SOURCE_DIR}/linking/samd21x18_bootloader_large.ld)
endif()

target_compile_options(shim PUBLIC ${target_c_flags})

target_link_libraries(shim
  -Os -Wl,--gc-sections -save-temps -T${linker_script} -nostdlib
  --specs=nano.specs --specs=nosys.specs -Wl,--cref -Wl,--check-sections
  -mcpu=${target_mcu} -mthumb
  -Wl,--gc-sections -Wl,--unresolved-symbols=report-all -Wl,--warn-common -Wl,--warn-section-align
)
