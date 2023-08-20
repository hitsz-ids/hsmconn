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
