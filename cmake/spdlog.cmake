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

