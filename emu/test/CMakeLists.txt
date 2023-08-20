find_package(Threads REQUIRED)
include(gtest)

set(test-source-pattern "*.cc" )
if (CMAKE_VERSION VERSION_GREATER 3.11)
  list(INSERT test-source-pattern 0 CONFIGURE_DEPENDS)
endif()

file(GLOB test-sources ${test-source-pattern})

add_executable(hsm-emu-tests "")
target_sources(hsm-emu-tests
  PRIVATE
    ${test-sources})

target_include_directories(hsm-emu-tests
  PRIVATE
    ${PROJECT_SOURCE_DIR}/emu/src/include)

target_link_libraries(hsm-emu-tests
  PRIVATE
    Threads::Threads
    absl::strings
    absl::memory
    hsm-emu
    ${_GTEST})

set_property(TARGET hsm-emu-tests PROPERTY CXX_STANDARD_REQUIRED ON)
if (NOT DEFINED CMAKE_CXX_STANDARD)
  set_target_properties(hsm-emu-tests PROPERTIES CXX_STANDARD 11)
endif()

add_test(hsmc::test hsm-emu-tests)

install(TARGETS hsm-emu-tests
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin)