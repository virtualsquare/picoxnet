cmake_minimum_required(VERSION 3.13)
project("piconet"
    DESCRIPTION "A tcp-ip stack for the IoTh"
    HOMEPAGE_URL "https://github.com/virtualsquare/picoxtcp"
    VERSION 0.1.0
    LANGUAGES C)

# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FORTIFY_SOURCE=2 -O2 -pedantic -Wall -Wextra")

include(GNUInstallDirs)
include(CheckIncludeFile)
include(CheckSymbolExists)

set(LIBS_REQUIRED pthread picotcp vdeplug vpoll fduserdata nlq)
set(HEADERS_REQUIRED libnlq.h vpoll.h linux/netlink.h)
set(CMAKE_REQUIRED_QUIET TRUE)
set(CMAKE_REQUIRED_LIBRARIES slirp)

foreach(THISLIB IN LISTS LIBS_REQUIRED)
  find_library(LIB${THISLIB}_OK ${THISLIB})
  if(NOT LIB${THISLIB}_OK)
    message(FATAL_ERROR "library lib${THISLIB} not found")
  endif()
endforeach(THISLIB)

foreach(HEADER IN LISTS HEADERS_REQUIRED)
  check_include_file(${HEADER} ${HEADER}_OK)
  if(NOT ${HEADER}_OK)
    message(FATAL_ERROR "header file ${HEADER} not found")
  endif()
endforeach(HEADER)

find_file(PICOTCP_H pico_tcp.h PATH_SUFFIXES picotcp REQUIRED)
get_filename_component(PICOTCP_INCLUDEDIR ${PICOTCP_H} DIRECTORY)

add_definitions(-D_GNU_SOURCE)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${PICOTCP_INCLUDEDIR})
# include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_library(picoxnet SHARED picoxnet.c pico_bsd_sockets.c picox_netlink.c picox_nl_ops.c)
target_link_libraries(picoxnet pthread picotcp vdeplug vpoll fduserdata nlq)

set_target_properties(picoxnet PROPERTIES VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})

# configure_file(picoxnet.pc.in picoxnet.pc @ONLY)
# configure_file(config.h.in config.h)

install(TARGETS picoxnet DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES picoxnet.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
#install(FILES ${CMAKE_CURRENT_BINARY_DIR}/picoxnet.pc
#        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

#add_subdirectory(man)

add_custom_target(uninstall
  "${CMAKE_COMMAND}" -P "${PROJECT_SOURCE_DIR}/Uninstall.cmake")

