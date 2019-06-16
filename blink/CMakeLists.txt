enable_arduino_toolchain()

if(TARGET_M4)
  enable_m4_board(${TARGET_BOARD})
endif()

if(TARGET_M0)
  enable_m0()
endif()

function(add_extra_targets target)
  get_target_property(binary_dir ${target} BINARY_DIR)

  add_custom_target(${target}.S ALL
    arm-none-eabi-objdump --disassemble ${binary_dir}/${target}.elf | c++filt > ${target}.S
    DEPENDS ${target}.elf
  )

  add_custom_target(${target}.dump ALL
    arm-none-eabi-objdump -s ${binary_dir}/${target}.elf | c++filt > ${target}.s
    DEPENDS ${target}.elf
  )

  add_custom_target(${target}.sections ALL
    arm-none-eabi-readelf --sections ${binary_dir}/${target}.elf > ${target}.sections
    DEPENDS ${target}.elf
  )

  add_custom_target(${target}.fkb ALL
    ${CMAKE_SOURCE_DIR}/tools/mkfirmware.py --elf ${binary_dir}/${target}.elf --fkb ${binary_dir}/${target}.fkb
    DEPENDS ${target}.elf
  )
endfunction()

file(GLOB blink_sources blink.cpp ../segger/*.c)

add_arduino_library(blink-reg "${blink_sources}")
target_include_directories(blink-reg PUBLIC ../)
target_compile_options(blink-reg PUBLIC -Wall -Werror)
add_arduino_firmware(blink-reg)
add_extra_targets(blink-reg)

add_arduino_library(blink-pic "${blink_sources}")
target_include_directories(blink-pic PUBLIC ../)
target_compile_options(blink-pic PUBLIC -Wall -Werror -fPIE -fno-inline -msingle-pic-base -mno-pic-data-is-text-relative)
add_arduino_firmware(blink-pic)
add_extra_targets(blink-pic)
