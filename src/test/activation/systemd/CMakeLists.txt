SET(SD_SYS_UNIT_DIR "${LIBDIR}/systemd/system")

SET(SD_SYS_UNITS
        resourced-test.service
)

INSTALL(FILES
	${CMAKE_CURRENT_BINARY_DIR}/${SD_SYS_UNITS}
        DESTINATION
        ${SD_SYS_UNIT_DIR}
)
