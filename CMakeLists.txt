cmake_minimum_required(VERSION 3.18)

project(Nested_HV LANGUAGES C CXX)

set(CMAKE_ASM_MASM_COMPILER "ml64")
enable_language(ASM_MASM)

# compile
add_compile_options("/utf-8")
add_compile_options("/EHs-c-")
add_compile_options("/GS-")
add_compile_options("/ZC:wchar_t-")
add_compile_options("/std:c++17")

# WDK path
set(ENV{WDKContentRoot} "E:/Windows Kits/10")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(WDK REQUIRED)

# sources
set(SOURCES
        src/main.cpp
        src/vmm.cpp
        src/asm/arch.asm
        src/header/common.h
        src/header/vmx.h
)

wdk_add_driver(Nested_HV ${SOURCES})

# link
set(WDK_KM_LIBS "E:/Windows Kits/10/Lib/10.0.26100.0/km/x64")
target_link_directories(Nested_HV PRIVATE "${WDK_KM_LIBS}")

target_link_libraries(Nested_HV
        WDK::NTOSKRNL
        WDK::HAL
        "${WDK_KM_LIBS}/wdmsec.lib"
)

# entry
set_target_properties(Nested_HV PROPERTIES LINK_FLAGS "/ENTRY:DriverEntry /INTEGRITYCHECK /SUBSYSTEM:NATIVE")