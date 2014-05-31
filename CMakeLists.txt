CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

INCLUDE(${CMAKE_SOURCE_DIR}/CMakeLists/init-needed-environment.txt)

INSTALL(FILES ${CMAKE_SOURCE_DIR}/system-resource.pc DESTINATION lib/pkgconfig)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/resourced.conf DESTINATION /etc/dbus-1/system.d)

INCLUDE(${CMAKE_SOURCE_DIR}/CMakeLists/init-cmake-projects.txt)
