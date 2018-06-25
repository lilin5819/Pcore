cmake_minimum_required(VERSION 3.0.0)
project(pcore VERSION 0.1.0)

include(CTest)
enable_testing()

include_directories(. include src src/pcore src/zmalloc src/sds src/dict src/cjson src/ae src/adlist)
aux_source_directory(src/zmalloc ZMALLOC_SRCS)
aux_source_directory(src/sds SDS_SRCS)
aux_source_directory(src/cjson CJSON_SRCS)
aux_source_directory(src/adlist ADLIST_SRCS)
aux_source_directory(src/dict DICT_SRCS)
aux_source_directory(src/pcore PCORE_SRCS)

set(AE_SRCS src/ae/ae.c src/ae/anet.c)
aux_source_directory(src MAIN_MSG_SRCS)
set(MAIN_SRCS src/main.c)

link_directories("." "./lib" "/usr/lib/x86_64-linux-gnu")
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)

# SLIBS
# add_library(zmalloc ${ZMALLOC_SRCS})
# add_library(sds ${SDS_SRCS} ${ZMALLOC_SRCS})
# add_library(ae ${AE_SRCS} ${ZMALLOC_SRCS})
# add_library(cjson ${CJSON_SRCS})
# add_library(adlist ${ADLIST_SRCS} ${ZMALLOC_SRCS})
# add_library(dict ${DICT_SRCS} ${ZMALLOC_SRCS})

#  DLIBS
add_library(zmalloc SHARED ${ZMALLOC_SRCS})
add_library(sds SHARED ${SDS_SRCS})
target_link_libraries(sds zmalloc)
add_library(adlist SHARED ${ADLIST_SRCS})
add_library(dict SHARED ${DICT_SRCS})
target_link_libraries(dict zmalloc)
add_library(ae SHARED ${AE_SRCS})
add_library(cjson SHARED ${CJSON_SRCS})
target_link_libraries(dict m)

set(EXT_DLIBS m uv zmalloc sds ae cjson adlist dict ssl crypto)

add_definitions(-DDEBUG)

# core
add_executable(pcore_core ${MAIN_SRCS} ${PCORE_SRCS})
add_dependencies(pcore_core adlist dict ae sds zmalloc cjson)
target_compile_definitions(pcore_core PUBLIC -DELINK_MODE=1 -DELINK_MODE_NAME="CORE")
target_link_libraries(pcore_core ${EXT_DLIBS})

# server
add_executable(pcore_server ${MAIN_MSG_SRCS} ${PCORE_SRCS})
add_dependencies(pcore_server adlist dict ae sds zmalloc cjson)
target_compile_definitions(pcore_server PUBLIC -DELINK_MODE=1 -DELINK_MODE_NAME="SERVER" -DCONFIG_MSG)
target_link_libraries(pcore_server ${EXT_DLIBS})

# client
add_executable(pcore_client ${MAIN_MSG_SRCS} ${PCORE_SRCS})
add_dependencies(pcore_client adlist dict ae sds zmalloc cjson)
target_compile_definitions(pcore_client PUBLIC -DELINK_MODE=0 -DELINK_MODE_NAME="CLIENT" -DCONFIG_MSG)
target_link_libraries(pcore_client ${EXT_DLIBS})

# test
add_executable(testae_timer test/testae_timer.c)
target_link_libraries(testae_timer ${EXT_DLIBS})

add_executable(testae_echo test/testae_echo.c)
target_link_libraries(testae_echo ${EXT_DLIBS})

add_executable(testuv_client test/testuv_client.c)
target_link_libraries(testuv_client ${EXT_DLIBS})

add_executable(test_dict test/test_dict.c)
target_link_libraries(test_dict ${EXT_DLIBS})

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
