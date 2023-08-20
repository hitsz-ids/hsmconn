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
