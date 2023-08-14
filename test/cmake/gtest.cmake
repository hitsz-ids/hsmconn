# cmake/gtest.cmake

if (GTEST_FETCHCONTENT)
    message(STATUS "Fetching https://github.com/google/googletest.git...")

    include(FetchContent)
    FetchContent_Declare(
            googletest
            GIT_REPOSITORY        https://github.com/google/googletest.git
            GIT_TAG               release-1.11.0
    )

    #FetchContent_GetProperties(googletest)
    #if(NOT googletest_POPULATED)
    #    FetchContent_Populate(googletest)
    #    add_subdirectory(${googletest_SOURCE_DIR} ${googletest_BINARY_DIR} EXCLUDE_FROM_ALL)
    #endif()

    set(INSTALL_GTEST OFF)
    set(BUILD_SHARED_LIBS OFF)
    FetchContent_MakeAvailable(googletest)
    set(_GTEST gtest)
else()
    find_package(GTest CONFIG REQUIRED)
    message(STATUS "Using GTest ${GTest_VERSION}")
    set(_GTEST GTest::gtest)
endif()



