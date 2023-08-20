include(gtest)

set(test-source-pattern "*.cc" )
if (CMAKE_VERSION VERSION_GREATER 3.11)
  list(INSERT test-source-pattern 0 CONFIGURE_DEPENDS)
endif()

file(GLOB test-sources ${test-source-pattern})

set(HSMC_TESTS hsmc-tests)
add_executable(${HSMC_TESTS} "")

target_compile_options(
        ${HSMC_TESTS} PRIVATE)

target_sources(${HSMC_TESTS}
  PRIVATE
    ${test-sources})

target_include_directories(${HSMC_TESTS}
  PRIVATE
    ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(${HSMC_TESTS}
  PRIVATE
    Threads::Threads
    hsmc
    hsm-emu
    absl::memory
    ${_GTEST}
    ${OPENTELEMETRY_RESOURCES}
    ${OPENTELEMETRY_OSTREAM_METRICS_EXPORTER}
    ${OPENTELEMETRY_API}
    ${OPENTELEMETRY_SDK})

set_property(TARGET ${HSMC_TESTS} PROPERTY CXX_STANDARD_REQUIRED ON)
if (NOT DEFINED CMAKE_CXX_STANDARD)
  set_target_properties(${HSMC_TESTS} PROPERTIES CXX_STANDARD 11)
endif()

add_test(hsmc::test ${HSMC_TESTS})
