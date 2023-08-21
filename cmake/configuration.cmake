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
#
# defines configuration options
# note: only include it in hsmc's top-level CMakeLists.txt
#
include(CMakeDependentOption)

# what to build
# examples/tests if toplevel directory (i.e. direct build, not as subdirectory) and hosted
# tools if hosted
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(HSMC_BUILD_FROM_TOPLEVEL 1)
else()
    set(HSMC_BUILD_FROM_TOPLEVEL 0)
endif()

option(HSMC_BUILD_TESTS 
  "If ON, will build the HSMC tests" ${HSMC_BUILD_FROM_TOPLEVEL})

option(HSMC_BUILD_HSMEMU 
  "If ON, will build the hsm emulator library" ON)

cmake_dependent_option(HSMC_BUILD_HSMEMU_TESTS
  "If ON, will build the hsm emulator tests"
  ON
  "HSMC_BUILD_TESTS;HSMC_BUILD_HSMEMU"
  OFF)

option(HSMC_BUILD_WITH_OPENTELEMETRY 
  "If ON, built with open telemetry API" OFF)

option(HSMC_BUILD_DOCS 
  "If ON, build and generate the documentation" OFF)

option(HSMC_BUILD_SHARED_LIBS 
  "If ON, build the shared libraries" ON)

cmake_dependent_option(HSMC_INSTALL
  "If ON, enable generation of install targets" ON
  "HSMC_BUILD_FROM_TOPLEVEL" OFF)
