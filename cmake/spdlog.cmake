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

# cmake/spdlog.cmake

find_package(spdlog QUIET)
if (NOT spdlog_FOUND)
    set(SPDLOG_GIT_REPO https://github.com/gabime/spdlog.git)
    set(SPDLOG_VERSION v1.11.0)
    message(STATUS "Fetching spdlog@${SPDLOG_VERSION} from repository ${SPDLOG_GIT_REPO}")

    include(FetchContent)
    FetchContent_Declare(
            spdlog
            GIT_REPOSITORY ${SPDLOG_GIT_REPO}
            GIT_TAG ${SPDLOG_VERSION})

    set(SPDLOG_BUILD_SHARED OFF)
    if (HSMC_INSTALL AND (NOT HSMC_BUILD_SHARED_LIBS))
        set(SPDLOG_INSTALL ON)
    endif()
    FetchContent_MakeAvailable(spdlog)
else()
    message(STATUS "Using spdlog ${spdlog_VERSION}")
endif()

