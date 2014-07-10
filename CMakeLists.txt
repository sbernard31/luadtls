cmake_minimum_required(VERSION 2.8)
find_package(Lua51 REQUIRED)

execute_process(COMMAND autoconf WORKING_DIRECTORY ../tinydtls)
execute_process(COMMAND ./configure WORKING_DIRECTORY ../tinydtls)

set(TINYDTLS_SOURCES_DIR ${CMAKE_CURRENT_LIST_DIR}/tinydtls)
set(TINYDTLS_SOURCES
	${TINYDTLS_SOURCES_DIR}/dtls.c
    ${TINYDTLS_SOURCES_DIR}/crypto.c
    ${TINYDTLS_SOURCES_DIR}/ccm.c
    ${TINYDTLS_SOURCES_DIR}/hmac.c
    ${TINYDTLS_SOURCES_DIR}/debug.c
    ${TINYDTLS_SOURCES_DIR}/netq.c
    ${TINYDTLS_SOURCES_DIR}/peer.c
    ${TINYDTLS_SOURCES_DIR}/dtls_time.c
    ${TINYDTLS_SOURCES_DIR}/session.c
    ${TINYDTLS_SOURCES_DIR}/sha2/sha2.c
    ${TINYDTLS_SOURCES_DIR}/aes/rijndael.c
    ${TINYDTLS_SOURCES_DIR}/sha2/sha2.c
    ${TINYDTLS_SOURCES_DIR}/ecc/ecc.c)

include_directories (${TINYDTLS_SOURCES_DIR})

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_FLAGS "-std=gnu99") 
add_definitions(-DWITH_SHA256)

add_library (core  SHARED src/lua_dtls_core.c ${TINYDTLS_SOURCES} )
set_target_properties(core PROPERTIES PREFIX "")
set_target_properties( core PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/dtls")

file(COPY src/init.lua DESTINATION "${CMAKE_BINARY_DIR}/dtls")
file(COPY sample/sample.lua DESTINATION "${CMAKE_BINARY_DIR}")
file(COPY sample/coresample.lua DESTINATION "${CMAKE_BINARY_DIR}")

