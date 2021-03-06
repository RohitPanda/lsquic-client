# Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE.
cmake_minimum_required(VERSION 2.8)


project(lsquic)

IF (NOT MSVC)
# We prefer clang
IF(NOT ("${CMAKE_C_COMPILER}" MATCHES "ccc-analyzer" OR
        "${CMAKE_C_COMPILER}" MATCHES "gcc"          OR
        "${CMAKE_C_COMPILER}" MATCHES "afl-gcc"))
    FIND_PROGRAM(CLANG "clang")
    IF(CLANG)
        SET(CMAKE_C_COMPILER "${CLANG}")
    ENDIF()
ENDIF()

ENDIF()

# If using older glibc, need to link with -lrt.  See clock_getres(2).
EXECUTE_PROCESS(
    COMMAND ${PROJECT_SOURCE_DIR}/print-glibc-version.sh ${CMAKE_C_COMPILER}
    OUTPUT_VARIABLE GLIBC_VERSION)
IF(NOT GLIBC_VERSION EQUAL "" AND GLIBC_VERSION VERSION_LESS 2.17)
    SET(LIBS ${LIBS} rt)
ENDIF()

# By default, we compile in development mode.  To compile production code,
# pass -DDEVEL_MODE=0 to cmake (before that, `make clean' and remove any
# cmake cache files).
#
IF(NOT DEFINED DEVEL_MODE)
    SET(DEVEL_MODE 1)
ENDIF()


MESSAGE(STATUS "DEVEL_MODE: ${DEVEL_MODE}")


IF (NOT MSVC)

SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -Wall -Wextra -Wno-unused-parameter")
SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -fno-omit-frame-pointer")

IF(CMAKE_COMPILER_IS_GNUCC AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 4.9.3)
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -Wno-missing-field-initializers")
ENDIF()
IF(DEVEL_MODE EQUAL 1)
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -O0 -g3")
    IF(CMAKE_C_COMPILER MATCHES "clang" AND
                        NOT "$ENV{TRAVIS}" MATCHES "^true$")
        SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -fsanitize=address")
    ENDIF()
    # Uncomment to enable fault injection testing via libfiu:
    #SET (MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DFIU_ENABLE=1")
    #SET(LIBS ${LIBS} fiu)
ELSE()
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -O3 -g0")
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DNDEBUG")
    # Comment out the following line to compile out debug messages:
    #SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DLSQUIC_LOWEST_LOG_LEVEL=LSQ_LOG_INFO")
ENDIF()

IF(LSQUIC_PROFILE EQUAL 1)
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -g -pg")
ENDIF()

IF(LSQUIC_COVERAGE EQUAL 1)
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -fprofile-arcs -ftest-coverage")
ENDIF()

IF(MY_CMAKE_FLAGS MATCHES "fsanitize=address")
    MESSAGE(STATUS "AddressSanitizer is ON")
ELSE()
    MESSAGE(STATUS "AddressSanitizer is OFF")
ENDIF()

#MSVC
ELSE()
SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -W4 -WX -Zi -DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_CRT_SECURE_NO_WARNINGS -I${CMAKE_CURRENT_SOURCE_DIR}/wincompat")
IF(DEVEL_MODE EQUAL 1)
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -Od")
    #SET (MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DFIU_ENABLE=1")
    #SET(LIBS ${LIBS} fiu)
ELSE()
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -Ox")
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DNDEBUG")
    # Comment out the following line to compile out debug messages:
    #SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DLSQUIC_LOWEST_LOG_LEVEL=LSQ_LOG_INFO")
ENDIF()

SET (BORINGSSL_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/../boringssl/include)
SET (VCPKG_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/../vcpkg/installed/x64-windows-static/include )
set (BORINGSSL_BASE_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../boringssl)

SET (VCPKG_BASE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../vcpkg/installed/x64-windows-static)

ENDIF() #MSVC

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  ${MY_CMAKE_FLAGS} $ENV{EXTRA_CFLAGS}")

MESSAGE(STATUS "Compiler flags: ${CMAKE_C_FLAGS}")

IF(NOT DEFINED BORINGSSL_INCLUDE)
    SET(BORINGSSL_INCLUDE /usr/local/include)
ENDIF()
IF(NOT DEFINED BORINGSSL_LIB)
    SET(BORINGSSL_LIB /usr/local/lib)
ENDIF()


include_directories(${BORINGSSL_INCLUDE} ${VCPKG_INCLUDE} )
link_directories( ${BORINGSSL_LIB}  )

SET(CMAKE_INCLUDE_CURRENT_DIR ON)
include_directories( include )
IF(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD" OR ${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    # Find libevent on FreeBSD:
    include_directories( /usr/local/include )
    link_directories( /usr/local/lib )
ENDIF()


IF (NOT MSVC)
add_executable(quic_perf
    test/http_client.c
    test/prog.c
    test/test_common.c
)
target_link_libraries(quic_perf lsquic event pthread libssl.a libcrypto.a ${LIBS} z m)

#MSVC
ELSE()
add_executable(quic_perf
    test/http_client.c
    test/prog.c
    test/test_common.c
    wincompat/getopt.c
    wincompat/getopt1.c
)

target_link_libraries(quic_perf
		debug  $(SolutionDir)src/liblsquic/debug/lsquic.lib
		debug  ${VCPKG_BASE_DIR}/debug/lib/event.lib
		debug  ${VCPKG_BASE_DIR}/debug/lib/zlibd.lib
		debug  ${BORINGSSL_BASE_LIB_DIR}/ssl/debug/ssl.lib
		debug  ${BORINGSSL_BASE_LIB_DIR}/crypto/debug/crypto.lib
		ws2_32
		optimized  $(SolutionDir)src/liblsquic/release/lsquic.lib
		optimized  ${VCPKG_BASE_DIR}/lib/event.lib
		optimized  ${VCPKG_BASE_DIR}/lib/zlib.lib
		optimized  ${BORINGSSL_BASE_LIB_DIR}/ssl/release/ssl.lib
		optimized  ${BORINGSSL_BASE_LIB_DIR}/crypto/release/crypto.lib
		${LIBS} )

ENDIF()

#target_link_libraries(quic_perf lsquic event pthread libssl.a libcrypto.a ${LIBS} z m)

add_subdirectory(src)

add_subdirectory(test)

IF(DEVEL_MODE EQUAL 1)
    # Our test framework relies on assertions, only compile if assertions are
    # enabled.
    #
    enable_testing()
ENDIF()


ADD_CUSTOM_TARGET(docs doxygen dox.cfg)

INSTALL(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/quic_perf
	  DESTINATION bin)

  SET(MAJOR_VERSION "1")
  SET(MINOR_VERSION "0")
  SET(PATCH_VERSION "0")
   
  IF(EXISTS "${CMAKE_ROOT}/Modules/CPack.cmake")
	  INCLUDE(InstallRequiredSystemLibraries)
	   
	  SET(CPACK_SET_DESTDIR "on")
	  SET(CPACK_PACKAGING_INSTALL_PREFIX "/tmp")
	  SET(CPACK_GENERATOR "DEB")
	   
	  SET(CPACK_PACKAGE_DESCRIPTION "Quic Measurements")
	  SET(CPACK_PACKAGE_VENDOR "rohit panda")
	  SET(CPACK_PACKAGE_CONTACT "rohit.panda@tum.de")
	  SET(CPACK_PACKAGE_VERSION_MAJOR "${MAJOR_VERSION}")
	  SET(CPACK_PACKAGE_VERSION_MINOR "${MINOR_VERSION}")
	  SET(CPACK_PACKAGE_VERSION_PATCH "${PATCH_VERSION}")
	  SET(CPACK_PACKAGE_FILE_NAME "quic_perf_${MAJOR_VERSION}.${MINOR_VERSION}.${CPACK_PACKAGE_VERSION_PATCH}")
	  SET(CPACK_SOURCE_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}_${MAJOR_VERSION}.${MINOR_VERSION}.${CPACK_PACKAGE_VERSION_PATCH}")
	   
	   
	  SET(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
	  SET(CPACK_DEBIAN_PACKAGE_SECTION "kde")
	  SET(CPACK_DEBIAN_ARCHITECTURE ${CMAKE_SYSTEM_PROCESSOR})
	   
	  SET(CPACK_COMPONENTS_ALL Libraries ApplicationData)
	  INCLUDE(CPack)
	   
  ENDIF(EXISTS "${CMAKE_ROOT}/Modules/CPack.cmake")
