project(loading)
cmake_minimum_required(VERSION 3.6)
set(CMAKE_MODULE_PATH $ENV{CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake)

include(Arduino)

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
    ${CMAKE_SOURCE_DIR}/tools/mkfirmware.py --elf ${binary_dir}/${target}.elf --fkb ${binary_dir}/${target}.fkb --shim ../shim/CMakeFiles/shim.dir/shim.c.o
    DEPENDS ${target}.elf
  )

  add_custom_target(${target}-fkb.bin)

  add_dependencies(${target}-fkb.bin ${target}.fkb)

  add_custom_command(TARGET ${target}-fkb.bin POST_BUILD COMMAND ${ARDUINO_OBJCOPY} -O binary
    ${CMAKE_CURRENT_BINARY_DIR}/${target}.fkb
    ${CMAKE_CURRENT_BINARY_DIR}/${target}-fkb.bin)

  add_custom_target(${target}_fkb_bin ALL DEPENDS ${target}-fkb.bin)
endfunction()

add_subdirectory(bootloader)
add_subdirectory(shim)
add_subdirectory(blink)
