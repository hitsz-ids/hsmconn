# builds actual library

set(header_path ${CMAKE_SOURCE_DIR}/include/hsmc)

find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
find_package(absl REQUIRED)

# third party dependencies
include(${CMAKE_SOURCE_DIR}/cmake/spdlog.cmake)

set(HSMC_SRC
        base/exception.cc
        session_pool.cc
        session_factory.cc
        session.cc
        session_impl.cc
        connector.cc
        pooled_session_holder.cc
        pooled_session_impl.cc
        vendors/bjca/connector.cc
        vendors/bjca/connector.h
        vendors/bjca/session_impl.cc
        vendors/bjca/session_impl.h
        vendors/ndsec/svs/session.cc
        vendors/ndsec/svs/session_impl.cc
        vendors/ndsec/svs/connector.cc
        vendors/ndsec/tss/connector.cc
        vendors/ndsec/tss/connector.h
        vendors/ndsec/tss/session_impl.cc
        vendors/ndsec/tss/session_impl.h
        vendors/ndsec/connector.cc
        vendors/ndsec/connector.h
        vendors/ndsec/session_impl.cc
        vendors/ndsec/session_impl.h
        vendors/emu/connector.cc
        vendors/emu/connector.h
        vendors/emu/session_impl.cc
        vendors/emu/session_impl.h
        vendors/fisec/connector.cc
        vendors/fisec/connector.h
        vendors/fisec/session_impl.cc
        vendors/fisec/session_impl.h
        vendors/fisec/svs/connector.cc
        vendors/fisec/svs/connector.h
        vendors/fisec/svs/session_impl.cc
        vendors/fisec/svs/session_impl.h
        vendors/sinocipher/svs/session.cc
        vendors/sinocipher/svs/connector.cc
        vendors/sinocipher/svs/session_impl.cc
        vendors/sinocipher/tss/connector.cc
        vendors/sinocipher/tss/connector.h
        vendors/sinocipher/tss/session_impl.cc
        vendors/sinocipher/tss/session_impl.h
        vendors/sinocipher/connector.cc
        vendors/sinocipher/connector.h
        vendors/sinocipher/session_impl.cc
        vendors/sinocipher/session_impl.h
        vendors/dean/connector.cc
        vendors/dean/connector.h
        vendors/dean/session_impl.cc
        vendors/dean/session_impl.h
        vendors/infosec/tss/connector.cc
        vendors/infosec/tss/connector.h
        vendors/infosec/tss/session_impl.cc
        vendors/infosec/tss/session_impl.h
        vendors/infosec/svs/session.cc
        vendors/infosec/svs/connector.cc
        vendors/infosec/svs/session_impl.cc
        vendors/sansec/connector.cc
        vendors/sansec/connector.h
        vendors/sansec/session_impl.cc
        vendors/sansec/session_impl.h
        utils/uuid.cc
        utils/uuid.h
        utils/logger.cc
        utils/log_internal.h
        )
# configure config file
configure_file("version.h.in" "${CMAKE_CURRENT_BINARY_DIR}/version.h")

set(HSMC_TARGET_NAME ${PROJECT_NAME})
add_library(${HSMC_TARGET_NAME}
        ${HSMC_SRC})
target_include_directories(${HSMC_TARGET_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}> # for generated files in build mode
        $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}>
        $<INSTALL_INTERFACE:include>)
target_compile_options(
        ${HSMC_TARGET_NAME} PRIVATE
        "-Wnon-virtual-dtor")

if(NOT MSVC)
    target_compile_features(hsmc PUBLIC cxx_constexpr)
endif()

if(${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang")
    if("${CMAKE_CXX_SIMULATE_ID}" STREQUAL "MSVC")
        target_compile_options(hsmc PRIVATE /WX /W3 /D _CRT_SECURE_NO_WARNINGS)
    else()
        target_compile_options(hsmc PRIVATE -pedantic-errors -Werror -Wall -Wextra -Wconversion -Wsign-conversion)
    endif()
elseif(${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU")
    target_compile_options(hsmc PRIVATE -pedantic-errors -Werror -Wall -Wextra -Wconversion -Wsign-conversion)
elseif(MSVC)
    target_compile_options(hsmc PRIVATE /WX /W3 /D _CRT_SECURE_NO_WARNINGS)
endif()

set_target_properties(${HSMC_TARGET_NAME} PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        POSITION_INDEPENDENT_CODE ON)

target_link_libraries(${HSMC_TARGET_NAME}
        ${SYMBOL_HIDDEN_FLAG}
        # abseil dependencies
        absl::strings
        absl::str_format
        absl::flat_hash_map
        absl::random_random
        # yaml parsing dependency
        ${_YAML_CPP}
        # logging dependency
        ${_SPDLOG}
        # metric dependency
        ${OPENTELEMETRY_API}
        ${CMAKE_DL_LIBS})

install(TARGETS ${HSMC_TARGET_NAME}
        EXPORT        hsmcTargets
        RUNTIME       DESTINATION ${HSMC_RUNTIME_INSTALL_DIR}
        LIBRARY       DESTINATION ${HSMC_LIBRARY_INSTALL_DIR}
        ARCHIVE       DESTINATION ${HSMC_ARCHIVE_INSTALL_DIR}
        PUBLIC_HEADER DESTINATION ${HSMC_INC_INSTALL_DIR})

# Write/install version file
include(CMakePackageConfigHelpers)
set(version_file "${CMAKE_CURRENT_BINARY_DIR}/cmake/hsmc-config-version.cmake")
write_basic_package_version_file(${version_file}
        VERSION ${PACKAGE_VERSION}
        COMPATIBILITY AnyNewerVersion)

install(DIRECTORY ${header_path}
        DESTINATION ${HSMC_INC_INSTALL_DIR})

install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/version.h
        DESTINATION ${HSMC_INC_INSTALL_DIR}/hsmc)

install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/hsmc.yaml"
        DESTINATION ${HSMC_ADDITIONAL_FILES_INSTALL_DIR})

install(FILES ${version_file}
        DESTINATION ${HSMC_CMAKE_CONFIG_INSTALL_DIR})