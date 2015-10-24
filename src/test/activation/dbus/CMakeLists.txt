SET(SYSTEM_DBUS_SERVICE_DIR "${PREFIX}/share/dbus-1/system-services")

INSTALL(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/org.tizen.system.resourced-test.service
        DESTINATION
        ${SYSTEM_DBUS_SERVICE_DIR}
)
