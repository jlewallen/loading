set(CMAKE_C_COMPILER arm-none-eabi-gcc)

add_library(shim SHARED shim.c)

if(TARGET_M4)
  target_compile_options(shim PUBLIC -Os -save-temps -nostdlib -fdata-sections -ffunction-sections)
endif()

if(TARGET_M0)
  target_compile_options(shim PUBLIC -Os -save-temps -nostdlib -fdata-sections -ffunction-sections)
endif()
