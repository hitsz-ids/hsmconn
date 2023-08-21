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

find_package(CLI11 CONFIG QUIET)
if (NOT CLI11_FOUND)
    set(CLI11_GIT_REPO https://github.com/CLIUtils/CLI11.git)
    set(CLI11_VERSION v2.1.2)
    message(STATUS "Fetching CLI11@${CLI11_VERSION} from repository ${CLI11_GIT_REPO}")

    include(FetchContent)
    FetchContent_Declare(
            CLI11
            GIT_REPOSITORY ${CLI11_GIT_REPO}
            GIT_TAG ${CLI11_VERSION})

    FetchContent_MakeAvailable(CLI11)
    set(_CLI11 CLI11)
else()
    message(STATUS "Using CLI11 ${CLI11_VERSION}")
    set(_CLI11 CLI11::CLI11)
endif()
