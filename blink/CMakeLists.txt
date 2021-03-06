enable_arduino_toolchain()

if(TARGET_M4)
  enable_m4_board(${TARGET_BOARD})
  set(linker_script ${CMAKE_SOURCE_DIR}/linking/samd51x20.ld)
endif()

if(TARGET_M0)
  enable_m0()
  set(linker_script ${CMAKE_SOURCE_DIR}/linking/samd21x18.ld)
endif()

file(GLOB blink_sources blink.cpp callbacks.c header.c ../segger/*.c ../segger/*.h)

if(0)
add_arduino_library(blink-reg "${blink_sources}")
target_include_directories(blink-reg PUBLIC ../ ../segger ../include)
target_compile_options(blink-reg PUBLIC -Wall -Werror)
configure_firmware_linker_script(blink-reg ${linker_script})
add_arduino_firmware(blink-reg)
add_extra_targets(blink-reg)
endif()

add_arduino_library(blink-pic "${blink_sources}")
target_include_directories(blink-pic PUBLIC ../ ../segger ../include)
target_compile_options(blink-pic PUBLIC -Wall -Werror -DFKB_ENABLE_HEADER -fpic -fno-inline -msingle-pic-base -mno-pic-data-is-text-relative)
configure_firmware_linker_script(blink-pic ${linker_script})
add_arduino_firmware(blink-pic)
add_extra_targets(blink-pic)

if(0)
add_arduino_library(blink-hdr "${blink_sources}")
target_include_directories(blink-hdr PUBLIC ../ ../segger ../include)
target_compile_options(blink-hdr PUBLIC -Wall -Werror -DFKB_ENABLE_HEADER)
configure_firmware_linker_script(blink-hdr ${linker_script})
add_arduino_firmware(blink-hdr)
add_extra_targets(blink-hdr)
endif()
