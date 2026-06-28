cmake_minimum_required(VERSION 3.14)
project(halo_trace C)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

if (NOT DEFINED DynamoRIO_DIR)
  message(FATAL_ERROR "Pass -DDynamoRIO_DIR=<dynamorio>/cmake")
endif ()

find_package(DynamoRIO REQUIRED)

add_library(halo_trace SHARED halo_trace.c)
configure_DynamoRIO_client(halo_trace)
use_DynamoRIO_extension(halo_trace drmgr)

install(TARGETS halo_trace LIBRARY DESTINATION lib)
