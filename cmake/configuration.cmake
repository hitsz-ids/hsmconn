# defines configuration options
# note: only include it in hsmc's top-level CMakeLists.txt

# what to build
# examples/tests if toplevel directory (i.e. direct build, not as subdirectory) and hosted
# tools if hosted
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(build_from_toplevel 1)
else()
    set(build_from_toplevel 0)
endif()
set(build_hsmemu 1)

option(HSMC_BUILD_TESTS "whether or not to build the tests" ${build_from_toplevel})
option(HSMC_BUILD_BENCHMARKS "whether or not to build the benchmark" ${build_from_toplevel})
option(HSMC_BUILD_HSMEMU "whether or not to build the hsm emulator library" ${build_hsmemu})
option(HSMC_BUILD_WITH_OPENTELEMETRY "whether or not to built with open telemetry API" OFF)
option(HSMC_BUILD_DOCS "whether or not to build the documentation" OFF)
option(BUILD_SHARED_LIBS "Build using shared libraries" ON)
