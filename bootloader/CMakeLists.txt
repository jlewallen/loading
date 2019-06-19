set(CMAKE_C_COMPILER arm-none-eabi-gcc)
set(CMAKE_C_COMPILER arm-none-eabi-gcc)

file(GLOB sources ../segger/*.c ../segger/*.h main.c)
add_library(bootloader STATIC ${sources})

if(TARGET_M0)
  set(target_mcu "cortex-m0plus")
  set(target_fcpu "48000000l")
  set(target_board_flags -DF_CPU=${target_fcpu} -D__SAMD21__ -D__SAMD21G18A__ -DARM_MATH_CM0PLUS)
  set(target_c_flags -Os -s -ffunction-sections -fdata-sections -nostdlib --param max-inline-insns-single=500 -MMD -mcpu=${target_mcu} -mthumb ${target_board_flags} -fstack-usage)
  set(linker_script ${CMAKE_CURRENT_SOURCE_DIR}/linking/samd21x18.ld)
endif()

if(TARGET_M4)
  set(target_mcu "cortex-m4")
  set(target_fcpu "120000000L")
  set(target_board_flags -DF_CPU=${target_fcpu} -D__SAMD51__ -D__FPU_PRESENT -DARM_MATH_CM4 -mfloat-abi=hard -mfpu=fpv4-sp-d16)
  set(target_c_flags -Os -s -ffunction-sections -fdata-sections -nostdlib --param max-inline-insns-single=500 -MMD -mcpu=${target_mcu} -mthumb ${target_board_flags} -fstack-usage)
  set(linker_script ${CMAKE_CURRENT_SOURCE_DIR}/linking/samd51x19.ld)
endif()

target_compile_options(bootloader PUBLIC ${target_c_flags})

target_include_directories(bootloader PUBLIC ../include)

add_custom_target(bootloader.elf)

add_dependencies(bootloader.elf bootloader)

# NOTE: -nostdlib here solves a weird conflicting architecture error.
add_custom_command(TARGET bootloader.elf POST_BUILD
    COMMAND ${CMAKE_C_COMPILER} -Os -save-temps -T${linker_script} -mcpu=${target_mcu} -mthumb -nostdlib
    --specs=nano.specs --specs=nosys.specs -Wl,--check-sections
    -Wl,--unresolved-symbols=report-all -Wl,--warn-common -Wl,--warn-section-align
    -o ${CMAKE_CURRENT_BINARY_DIR}/bootloader.elf
    ${CMAKE_CURRENT_BINARY_DIR}/libbootloader.a
  )


add_custom_target(bootloader_bin ALL DEPENDS bootloader.elf)
