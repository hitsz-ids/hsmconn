# cmake/gtest.cmake

find_package(GTest CONFIG QUIET)
if (NOT gtest_FOUND)
    set(GTEST_GIT_REPO https://github.com/google/googletest.git)
    set(GTEST_VERSION release-1.11.0)
    message(STATUS "Fetching gtest@${GTEST_VERSION} from repository ${GTEST_GIT_REPO}")

    include(FetchContent)
    FetchContent_Declare(
            googletest
            GIT_REPOSITORY        ${GTEST_GIT_REPO}
            GIT_TAG               ${GTEST_VERSION}
    )

    set(INSTALL_GTEST OFF CACHE BOOL "")
    set(BUILD_GMOCK OFF CACHE BOOL "")
    FetchContent_MakeAvailable(googletest)
    set(_GTEST gtest)
else()
    message(STATUS "Using GTest ${GTest_VERSION}")
    set(_GTEST GTest::gtest)
endif()



