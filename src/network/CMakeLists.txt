SET(CMAKE_INSTALL_PREFIX /usr)
SET(PREFIX ${CMAKE_INSTALL_PREFIX})

SET(PROJECT ${RESOURCED})
PROJECT(${PROJECT})

IF("${NETWORK_MODULE}" STREQUAL "OFF")
	INCLUDE_DIRECTORIES(${INCLUDE_PUBLIC_DIR}
			${INCLUDE_COMMON_DIR})
	SET(SOURCES ${NETWORK_SOURCE_DIR}/join-dummy.c)
	ADD_LIBRARY(${PROJECT} SHARED ${SOURCES})
	TARGET_LINK_LIBRARIES(${PROJECT} ${shared_pkgs_LDFLAGS})

	SET_TARGET_PROPERTIES(${PROJECT}
			PROPERTIES
			VERSION ${FULLVER}
			SOVERSION ${MAJORVER}
			CLEAN_DIRECT_OUTPUT 1
	)

	INSTALL(TARGETS ${PROJECT} DESTINATION lib)

	RETURN()
ENDIF()

INCLUDE_DIRECTORIES(${INCLUDE_PUBLIC_DIR}
		${NETWORK_SOURCE_DIR}/include
		${RESOURCED_INCLUDEDIR}
	)

SET (REQUIRES_LIST dlog
		   glib-2.0
		   sqlite3
		   vconf
		   ecore
		   edbus
)

IF("${TETHERING_FEATURE}" STREQUAL "ON")
	SET(REQUIRES_LIST ${REQUIRES_LIST}
		   capi-network-connection)
ENDIF()

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs_${NETWORK} REQUIRED ${REQUIRES_LIST})

FOREACH(flag ${pkgs_${NETWORK}_CFLAGS})
    SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -fPIC -Wall -Werror")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g")


IF("${ARCH}" STREQUAL "arm")
    ADD_DEFINITIONS("-DTARGET")
ENDIF("${ARCH}" STREQUAL "arm")

ADD_DEFINITIONS("-DPREFIX=\"${CMAKE_INSTALL_PREFIX}\"")
ADD_DEFINITIONS("-DSLP_DEBUG")

IF("${NETWORK_SERVICE}" STREQUAL "OFF")
	ADD_DEFINITIONS("-DNETWORK_SERVICE_OFF")
ENDIF()

#### libs ####

SET(settings_HEADERS
  ${NETWORK_SOURCE_DIR}/include/settings.h)

SET(settings_SOURCES
  ${NETWORK_SOURCE_DIR}/settings.c)

ADD_LIBRARY(settings STATIC
  ${settings_SOURCES})

SET(storage_HEADERS
  ${NETWORK_SOURCE_DIR}/include/storage.h)

SET(storage_SOURCES
  ${NETWORK_SOURCE_DIR}/datausage-quota-processing.c #storage uses it
  ${NETWORK_SOURCE_DIR}/storage.c)

SET(protocol-info_HEADERS
  ${NETWORK_SOURCE_DIR}/include/protocol-info.h)

SET(protocol-info_SOURCES
  ${NETWORK_SOURCE_DIR}/protocol-info.c)

SET(quota_HEADERS
  ${NETWORK_SOURCE_DIR}/include/datausage-quota-processing.h)

SET(quota_SOURCES
  ${COMMON_SOURCE_DIR}/edbus-handler.c
  ${NETWORK_SOURCE_DIR}/datausage-quota.c
  )

SET(app-stat_HEADERS
  ${INCLUDE_COMMON_DIR}/app-stat.h)

SET(app-stat_SOURCES
  ${NETWORK_SOURCE_DIR}/app-stat.c)

SET(net-iface_HEADERS
  ${NETWORK_SOURCE_DIR}/include/iface.h)

SET(net-iface_SOURCES
  ${NETWORK_SOURCE_DIR}/iface.c
)

SET(roaming_HEADERS
  ${NETWORK_SOURCE_DIR}/include/roaming.h)

SET(roaming_SOURCES
  ${NETWORK_SOURCE_DIR}/dummy_roaming.c)

ADD_LIBRARY(protocol-info STATIC
  ${protocol-info_SOURCES} ${protocol-info_HEADERS})

ADD_LIBRARY(storage STATIC
  ${storage_SOURCES} ${storage_HEADERS}
  ${quota_SOURCES} ${quota_HEADERS}
  )
TARGET_LINK_LIBRARIES(storage protocol-info ${pkgs_${NETWORK}_LDFLAGS})

ADD_LIBRARY(app-stat STATIC
  ${app-stat_SOURCES} ${app-stat_HEADERS})
TARGET_LINK_LIBRARIES(app-stat net-cls)

ADD_LIBRARY(net-iface STATIC
  ${net-iface_SOURCES})

ADD_LIBRARY(roaming STATIC
  ${roaming_SOURCES})
TARGET_LINK_LIBRARIES(roaming ${pkgs_${NETWORK}_LDFLAGS})

SET(net-cls_HEADERS
  ${NETWORK_SOURCE_DIR}/include/net-cls-cgroup.h)

SET(net-cls_SOURCES
  ${NETWORK_SOURCE_DIR}/net-cls-cgroup.c)

ADD_LIBRARY(net-cls STATIC
  ${net-cls_SOURCES})

#### libs ####

#### lib-resourced ####

SET(${PROJECT}_HEADERS
  ${INCLUDE_PUBLIC_DIR}/data_usage.h
  ${INCLUDE_PUBLIC_DIR}/resourced.h
  ${INCLUDE_COMMON_DIR}/const.h
  ${INCLUDE_COMMON_DIR}/trace.h
  ${quota_HEADERS}
  )

SET(${PROJECT}_SOURCES
  ${COMMON_SOURCE_DIR}/cgroup.c
  ${COMMON_SOURCE_DIR}/appid-helper.c
  ${COMMON_SOURCE_DIR}/file-helper.c
  ${NETWORK_SOURCE_DIR}/foreach.c
  ${NETWORK_SOURCE_DIR}/join.c
  ${NETWORK_SOURCE_DIR}/options.c
  ${NETWORK_SOURCE_DIR}/reset.c
  ${NETWORK_SOURCE_DIR}/restriction.c
  ${NETWORK_SOURCE_DIR}/update.c
  ${NETWORK_SOURCE_DIR}/main.c
  ${NETWORK_SOURCE_DIR}/nl-helper.c
  ${NETWORK_SOURCE_DIR}/restriction-helper.c
  ${quota_SOURCES}
  )

IF("${DATAUSAGE_TYPE}" STREQUAL "NFACCT")
ELSE()
  SET(${PROJECT}_SOURCES ${${PROJECT}_SOURCES}
    ${NETWORK_SOURCE_DIR}/net-activity.c
    ${NETWORK_SOURCE_DIR}/generic-netlink.c
  )
ENDIF()


INCLUDE(FindPkgConfig)
pkg_check_modules(shared_pkgs REQUIRED dlog
				       glib-2.0
				       sqlite3
				       vconf
				       ecore
				       edbus)

FOREACH(flag ${shared_pkgs_CFLAGS})
        SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fPIC")

INCLUDE_DIRECTORIES(${RESOURCED_INCLUDEDIR}
		    ${NETWORK_SOURCE_DIR}/include
		    ${RESOURCED_SOURCE_DIR})

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")

ADD_LIBRARY(${PROJECT} SHARED
  ${${PROJECT}_HEADERS}
  ${${PROJECT}_SOURCES})

TARGET_LINK_LIBRARIES(${PROJECT} roaming settings net-cls
  ${shared_pkgs_LDFLAGS})

SET_TARGET_PROPERTIES(${PROJECT}
     PROPERTIES
     VERSION ${FULLVER}
     SOVERSION ${MAJORVER}
     CLEAN_DIRECT_OUTPUT 1
)

ADD_EXECUTABLE(datausagetool ${UTILS_SOURCE_DIR}/datausage-tool.c)
TARGET_LINK_LIBRARIES(datausagetool
		      ${PROJECT}
		      ${COMMON_SOURCE_DIR}/config-parser.c
		      net-iface)
INSTALL(TARGETS datausagetool
    DESTINATION /usr/bin)

INSTALL(TARGETS ${PROJECT} DESTINATION lib)
INSTALL(FILES ${INCLUDE_PUBLIC_DIR}/data_usage.h DESTINATION include/system)
#### lib-resourced ####

#### rd-network ####
SET(SOURCES
	${NETWORK_SOURCE_DIR}/network-dummy.c)

ADD_LIBRARY(${NETWORK} SHARED ${SOURCES})
ADD_DEPENDENCIES(${NETWORK} ${PROJECT})
TARGET_LINK_LIBRARIES(${NETWORK} ${${NETWORK}_LDFLAGS} -L${LIBRARY_OUTPUT_PATH} -l${PROJECT})

SET_TARGET_PROPERTIES(${NETWORK}
     PROPERTIES
     VERSION ${FULLVER}
     SOVERSION ${MAJORVER}
     CLEAN_DIRECT_OUTPUT 1
)

INSTALL(TARGETS ${NETWORK} DESTINATION lib)
INSTALL(FILES ${INCLUDE_PUBLIC_DIR}/rd-network.h DESTINATION include/system)

#### rd-network ####
