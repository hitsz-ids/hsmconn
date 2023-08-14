if (CLI11_FETCHCONTENT)
    set(CLI11_GIT_REPO https://github.com/CLIUtils/CLI11.git)
    message(STATUS "Using CLI11 via FetchContent from ${CLI11_GIT_REPO}")

    include(FetchContent)
    FetchContent_Declare(
            CLI11
            GIT_REPOSITORY ${CLI11_GIT_REPO}
            GIT_TAG v2.1.2)

    FetchContent_MakeAvailable(CLI11)
    set(_CLI11 CLI11)
else()
    find_package(CLI11 CONFIG REQUIRED)
    message(STATUS "Using CLI11 ${CLI11_VERSION}")
    set(_CLI11 CLI11::CLI11)
endif()
