cmake_minimum_required(VERSION 3.5)

project(teeth LANGUAGES C)
set(CMAKE_C_STANDARD 11)

include_directories(inc)

if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DNDEBUG=1)
endif()


add_library(lib STATIC
    src/lib.c
    src/lib.h)

add_executable(teethd src/teethd.c inc/teeth.h)
target_link_libraries(teethd PRIVATE lib)
set_target_properties(teethd PROPERTIES PUBLIC_HEADER inc/teeth.h)

add_executable(teeth-gen src/teeth-gen.c)
target_link_libraries(teeth-gen PRIVATE lib)

add_executable(teeth-dump src/teeth-dump.c)
target_link_libraries(teeth-dump PRIVATE lib)

install(
    TARGETS
    teeth-gen teeth-dump teethd
    DESTINATION bin
    PUBLIC_HEADER DESTINATION include)

