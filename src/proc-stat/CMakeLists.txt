SET(CMAKE_INSTALL_PREFIX /usr)
SET(PREFIX ${CMAKE_INSTALL_PREFIX})

INCLUDE_DIRECTORIES(${RESOURCED_INCLUDEDIR}
	${PROC-STAT_SOURCE_DIR}/include)

SET (REQUIRES_LIST dlog glib-2.0)

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs_proc_stat REQUIRED ${REQUIRES_LIST})

FOREACH(flag ${pkgs_proc_stat_CFLAGS})
    SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -fPIC -Wall -Werror")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g")

IF("${ARCH}" STREQUAL "arm")
    ADD_DEFINITIONS("-DTARGET")
ENDIF("${ARCH}" STREQUAL "arm")

ADD_DEFINITIONS("-DPREFIX=\"${CMAKE_INSTALL_PREFIX}\"")
ADD_DEFINITIONS("-DSLP_DEBUG")

SET(SOURCES
	${PROC-STAT_SOURCE_DIR}/proc-stat.c)

ADD_LIBRARY(${PROC-STAT} SHARED ${SOURCES})

TARGET_LINK_LIBRARIES(${PROC-STAT} ${pkgs_proc_stat_LDFLAGS})

SET_TARGET_PROPERTIES(${PROC-STAT}
     PROPERTIES
     VERSION ${FULLVER}
     SOVERSION ${MAJORVER}
     CLEAN_DIRECT_OUTPUT 1
)


INSTALL(TARGETS ${PROC-STAT} DESTINATION lib)
INSTALL(FILES ${INCLUDE_PUBLIC_DIR}/proc_stat.h DESTINATION include/system)

IF(UNIX)

ADD_CUSTOM_TARGET (distclean @echo cleaning for source distribution)
ADD_CUSTOM_COMMAND(
        DEPENDS clean
        COMMENT "distribution clean"
        COMMAND find
        ARGS    .
        -not -name config.cmake -and \(
        -name CMakeFiles -or
        -name cmake.depends -or
        -name cmake.check_depends -or
        -name CMakeCache.txt -or
        -name cmake.check_cache -or
        -name *.cmake -or
        -name Makefile -or
        -name core -or
        -name core.* -or
        -name gmon.out -or
        -name install_manifest.txt -or
        -name *.pc -or
        -name *~ \)
        | grep -v TC | xargs rm -rf
        TARGET  distclean
        VERBATIM
)

ENDIF(UNIX)
