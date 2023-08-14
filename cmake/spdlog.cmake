# cmake/spdlog.cmake

if (SPDLOG_FETCHCONTENT)
    set(SPDLOG_GIT_REPO https://github.com/gabime/spdlog.git)
    message(STATUS "Using spdlog via FetchContent from ${SPDLOG_GIT_REPO}")

    include(FetchContent)
    FetchContent_Declare(
            spdlog
            GIT_REPOSITORY ${SPDLOG_GIT_REPO}
            GIT_TAG v1.11.0)

    set(BUILD_SHARED_LIBS OFF)
    FetchContent_MakeAvailable(spdlog)
    set(_SPDLOG spdlog)
else()
    find_package(spdlog REQUIRED)
    message(STATUS "Using spdlog ${spdlog_VERSION}")
    set(_SPDLOG spdlog::spdlog)
endif()

