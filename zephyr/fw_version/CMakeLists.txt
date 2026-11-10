cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(fw_version)

# Firmware version string is injected at build time: west build ... -- -DFW_VERSION=1.1
if(NOT DEFINED FW_VERSION)
  set(FW_VERSION "0.0")
endif()
target_compile_definitions(app PRIVATE FW_VERSION_STR="${FW_VERSION}")
target_sources(app PRIVATE src/main.c)
