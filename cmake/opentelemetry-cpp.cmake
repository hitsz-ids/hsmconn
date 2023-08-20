# cmake/opentelemetry-cpp.cmake

find_package(opentelemetry-cpp QUIET)
if (NOT opentelemetry-cpp_FOUND)
    set(OPENTELEMETRYCPP_GIT_REPO https://github.com/open-telemetry/opentelemetry-cpp.git)
    set(OPENTELEMETRYCPP_VERSION v1.8.0)
    message(STATUS "Fetching opentelemetry-cpp@${OPENTELEMETRYCPP_VERSION} from repository ${OPENTELEMETRYCPP_GIT_REPO}")

    include(FetchContent)
    FetchContent_Declare(
            opentelemetry-cpp
            GIT_REPOSITORY ${OPENTELEMETRYCPP_GIT_REPO}
            GIT_TAG ${OPENTELEMETRYCPP_VERSION})

    set(WITH_ABSEIL ON)
    set(WITH_BENCHMARK OFF)
    set(WITH_EXAMPLES OFF)
    set(BUILD_TESTING OFF)
    #enable prometheus export
    #set(WITH_PROMETHEUS ON)
    FetchContent_MakeAvailable(opentelemetry-cpp)

    set(OPENTELEMETRY_API opentelemetry-cpp::api)
    set(OPENTELEMETRY_SDK opentelemetry-cpp::sdk)
    add_definitions(-DENABLE_OPENTELEMETRY_API)
else()
    message(STATUS "Using opentelemetry-cpp ${opentelemetry-cpp_VERSION}")

    set(OPENTELEMETRY_API opentelemetry-cpp::api)
    set(OPENTELEMETRY_SDK opentelemetry-cpp::sdk)
    set(OPENTELEMETRY_RESOURCES opentelemetry-cpp::resources)
    set(OPENTELEMETRY_OSTREAM_METRICS_EXPORTER opentelemetry-cpp::ostream_metrics_exporter)
    add_definitions(-DENABLE_OPENTELEMETRY_API)
endif()
