find_package(Doxygen)

if (DOXYGEN_FOUND)
	set(DOXYGEN_INPUT_DIR "${DOXYGEN_INPUT_DIR} ${PROJECT_SOURCE_DIR}/include")
	set(DOXYGEN_INPUT_DIR "${DOXYGEN_INPUT_DIR} ${PROJECT_SOURCE_DIR}/src")
	set(DOXYGEN_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/doxygen)
	set(DOXYFILE_IN ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)
	set(DOXYFILE_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

	#Replace variables inside @@ with the current values
	configure_file(${DOXYFILE_IN} ${DOXYFILE_OUT} @ONLY)

	add_custom_target(Doxygen ALL
		COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYFILE_OUT}
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		COMMENT "Generating API documentation with Doxygen"
		VERBATIM)

	# Add an install target to install the docs
	include(GNUInstallDirs)
	install(DIRECTORY ${DOXYGEN_OUTPUT_DIR}
		DESTINATION ${CMAKE_INSTALL_DOCDIR})

else (DOXYGEN_FOUND)
	message(WARNING "Doxygen need to be installed to generate the documentation")
endif(DOXYGEN_FOUND)


