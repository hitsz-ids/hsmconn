# set target name
set(EMULATOR_LIB_TARGET_NAME hsm-emu)
set(EMULATOR_TOOL_TARGET_NAME hsm-emu-tool)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

include(CLI11)

set(EMULATOR_LIB_SRC src/emulator.cc)
add_library(${EMULATOR_LIB_TARGET_NAME} SHARED ${EMULATOR_LIB_SRC})
target_include_directories(${EMULATOR_LIB_TARGET_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/include
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)
target_link_libraries(${EMULATOR_LIB_TARGET_NAME}
    PUBLIC
        ${SYMBOL_HIDDEN_FLAG}
        OpenSSL::Crypto
        ${CMAKE_DL_LIBS}
    PRIVATE
        absl::strings
        absl::str_format
        ${_YAML_CPP})
set_target_properties(${EMULATOR_LIB_TARGET_NAME} PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR})

add_executable(${EMULATOR_TOOL_TARGET_NAME} src/emutool.cc)
target_include_directories(${EMULATOR_TOOL_TARGET_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/include
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)
target_link_libraries(${EMULATOR_TOOL_TARGET_NAME}
    PUBLIC
        ${SYMBOL_HIDDEN_FLAG}
        OpenSSL::Crypto
    PRIVATE
        absl::strings
        absl::str_format
        ${_CLI11}
        ${_YAML_CPP})

if(HSMC_BUILD_HSMEMU_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()

if(HSMC_INSTALL)
    # 将库文件，可执行文件，头文件安装到指定目录
    install(TARGETS ${EMULATOR_LIB_TARGET_NAME} ${EMULATOR_TOOL_TARGET_NAME}
        EXPORT  hsmcTargets
        LIBRARY DESTINATION ${HSMC_LIBRARY_INSTALL_DIR}
        RUNTIME DESTINATION ${HSMC_RUNTIME_INSTALL_DIR})

    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/hsm-emu.yaml"
        DESTINATION ${HSMC_ADDITIONAL_FILES_INSTALL_DIR})
endif()
