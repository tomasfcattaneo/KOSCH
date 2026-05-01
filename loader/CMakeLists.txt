cmake_minimum_required(VERSION 3.20)
project(koshchei_loader LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W4 /WX /GS- /MT /O2)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN)
endif()

file(GLOB LOADER_SOURCES src/*.c)
file(GLOB LOADER_HEADERS src/*.h)

add_executable(koshchei ${LOADER_SOURCES} ${LOADER_HEADERS})

target_link_libraries(koshchei PRIVATE
    ntdll
    advapi32
    psapi
)

set_target_properties(koshchei PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/$<CONFIG>"
    OUTPUT_NAME "koshchei"
)
