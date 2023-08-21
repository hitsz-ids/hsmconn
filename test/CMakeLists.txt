# Copyright (C) 2021 Institute of Data Security, HIT
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
