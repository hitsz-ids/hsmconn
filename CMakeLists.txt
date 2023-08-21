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

cmake_minimum_required(VERSION 3.14)
project(hsmc VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_MACOSX_RPATH 1)

find_package(Threads REQUIRED)

list(APPEND CMAKE_MODULE_PATH
    ${CMAKE_CURRENT_LIST_DIR}/cmake
)

# installation destinations
if(UNIX OR VXWORKS)
    include(GNUInstallDirs)

    set(HSMC_INC_INSTALL_DIR "${CMAKE_INSTALL_INCLUDEDIR}")
    set(HSMC_RUNTIME_INSTALL_DIR "${CMAKE_INSTALL_BINDIR}")
    set(HSMC_LIBRARY_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}")
    set(HSMC_ARCHIVE_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}")

    set(HSMC_CMAKE_CONFIG_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/hsmc/cmake")
    set(HSMC_ADDITIONAL_FILES_INSTALL_DIR "${CMAKE_INSTALL_DATADIR}/hsmc")
else()
    message(FATAL_ERROR "Could not set install folders for this platform!")
endif()

include(configuration)
include(abseil-cpp)
include(yaml-cpp)

if(HSMC_BUILD_SHARED_LIBS)
    set(hsmc-type SHARED)
else()
    set(hsmc-type STATIC)
endif()

# subdirectories
add_subdirectory(src)
if(HSMC_BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()

if(HSMC_BUILD_HSMEMU)
    add_subdirectory(emu)
endif()

if(HSMC_BUILD_DOCS)
    # Add the cmake folder so the FindSphinx module is found
    set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
    add_subdirectory(docs)
endif()

if(HSMC_INSTALL)
    # install readme and license
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE" "${CMAKE_CURRENT_SOURCE_DIR}/README.md"
            DESTINATION ${HSMC_ADDITIONAL_FILES_INSTALL_DIR})

    install(EXPORT hsmcTargets
            FILE hsmcTargets.cmake
            NAMESPACE hsmc::
            DESTINATION ${HSMC_CMAKE_CONFIG_INSTALL_DIR})

    configure_file(hsmc-config.cmake.in hsmc-config.cmake @ONLY)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/hsmc-config.cmake"
            DESTINATION ${HSMC_CMAKE_CONFIG_INSTALL_DIR})
endif()
