# cmake/yaml-cpp.cmake

if (YAMLCPP_FETCHCONTENT)
    set(YAMLCPP_GIT_REPO https://github.com/jbeder/yaml-cpp.git)
    set(YAMLCPP_VERSION yaml-cpp-0.7.0)

    message(STATUS "Using yaml-cpp ${YAMLCPP_VERSION} via FetchContent")

    include(FetchContent)
    FetchContent_Declare(
            yaml-cpp
            GIT_REPOSITORY ${YAMLCPP_GIT_REPO}
            GIT_TAG ${YAMLCPP_VERSION})

    set(YAML_CPP_INSTALL OFF)
    set(YAML_CPP_BUILD_TESTS OFF)
    set(YAML_CPP_BUILD_TOOLS OFF)
    FetchContent_MakeAvailable(yaml-cpp)
    set(_YAML_CPP yaml-cpp)
else()
    find_package(yaml-cpp REQUIRED)
    message(STATUS "Using yaml-cpp ${yaml-cpp_VERSION}")
    #set(_YAML_CPP yaml-cpp::yaml-cpp)
    set(_YAML_CPP yaml-cpp)
endif()
