enable_arduino_toolchain()

if(TARGET_M4)
  enable_m4_board(${TARGET_BOARD})
endif()

if(TARGET_M0)
  enable_m0()
endif()


file(GLOB blink_sources blink.cpp ../segger/*.c)
add_arduino_library(blink "${blink_sources}")
target_include_directories(blink PUBLIC ../)
target_compile_options(blink PUBLIC -Wall -Werror)
add_arduino_firmware(blink)

get_target_property(blink_dir blink BINARY_DIR)

add_custom_target(blink.S ALL
  arm-none-eabi-objdump --disassemble ${blink_dir}/blink.elf | c++filt > blink.S
  DEPENDS blink.elf
)

add_custom_target(blink.dump ALL
  arm-none-eabi-objdump -s ${blink_dir}/blink.elf | c++filt > blink.s
  DEPENDS blink.elf
  )

add_custom_target(blink.sections ALL
  arm-none-eabi-readelf --sections ${blink_dir}/blink.elf > blink.sections
  DEPENDS blink.elf
)


file(GLOB blink_pic_sources blink.cpp ../segger/*.c)
add_arduino_library(blink-pic "${blink_pic_sources}")
target_include_directories(blink-pic PUBLIC ../)
target_compile_options(blink-pic PUBLIC -Wall -Werror -fPIE -fno-inline -msingle-pic-base -mno-pic-data-is-text-relative)
add_arduino_firmware(blink-pic)

get_target_property(blink_pic_dir blink-pic BINARY_DIR)

add_custom_target(blink-pic.S ALL
  arm-none-eabi-objdump --disassemble ${blink_pic_dir}/blink-pic.elf | c++filt > blink-pic.S
  DEPENDS blink-pic.elf
)

add_custom_target(blink-pic.dump ALL
  arm-none-eabi-objdump -s ${blink_pic_dir}/blink-pic.elf | c++filt > blink-pic.s
  DEPENDS blink-pic.elf
)

add_custom_target(blink-pic.sections ALL
  arm-none-eabi-readelf --sections ${blink_pic_dir}/blink-pic.elf > blink-pic.sections
  DEPENDS blink-pic.elf
)
