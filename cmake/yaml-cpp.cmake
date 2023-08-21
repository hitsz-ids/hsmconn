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

# cmake/yaml-cpp.cmake

find_package(yaml-cpp QUIET)

if (NOT yaml-cpp_FOUND)
    set(YAMLCPP_GIT_REPO https://github.com/jbeder/yaml-cpp.git)
    set(YAMLCPP_VERSION 0.8.0)

    message(STATUS "Fetching yaml-cpp@${YAMLCPP_VERSION} from repository ${YAMLCPP_GIT_REPO}")

    include(FetchContent)
    FetchContent_Declare(
            yaml-cpp
            GIT_REPOSITORY ${YAMLCPP_GIT_REPO}
            GIT_TAG ${YAMLCPP_VERSION})

    set(YAML_CPP_BUILD_TESTS OFF)
    if(HSMC_INSTALL AND (NOT HSMC_BUILD_SHARED_LIBS))
        set(YAML_CPP_INSTALL ON CACHE BOOL "")
    endif()
    FetchContent_MakeAvailable(yaml-cpp)
    set(_YAML_CPP yaml-cpp)
else()
    message(STATUS "Using yaml-cpp ${yaml-cpp_VERSION}")
    set(_YAML_CPP yaml-cpp)
endif()
