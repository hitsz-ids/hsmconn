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

find_package(absl QUIET)

if (NOT absl_FOUND)
    set(ABSL_GIT_REPO https://github.com/abseil/abseil-cpp.git)
    set(ABSL_VERSION 20230802.0)

    message(STATUS "Fetching abseil-cpp@${ABSL_VERSION} from repository ${ABSL_GIT_REPO}")

    include(FetchContent)
    FetchContent_Declare(
            abseil-cpp
            GIT_REPOSITORY ${ABSL_GIT_REPO}
            GIT_TAG ${ABSL_VERSION})

    set(ABSL_PROPAGATE_CXX_STD ON)
    if (HSMC_INSTALL AND (NOT HSMC_BUILD_SHARED_LIBS))
        set(ABSL_ENABLE_INSTALL ON)
    endif()
    FetchContent_MakeAvailable(abseil-cpp)
else()
    message(STATUS "Using abseil-cpp@${absl_VERSION}")
endif()
