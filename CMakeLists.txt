cmake_minimum_required(VERSION 3.0.0)
project(pcore VERSION 0.1.0)

add_definitions(-DDEBUG)
link_directories("." "./lib" "/usr/lib/x86_64-linux-gnu")
include_directories(. include src/zmalloc src/sds src/dict src/cjson src/ae src/adlist)
aux_source_directory(src/zmalloc ZMALLOC_SRCS)
aux_source_directory(src/sds SDS_SRCS)
aux_source_directory(src/cjson CJSON_SRCS)
aux_source_directory(src/adlist ADLIST_SRCS)
aux_source_directory(src/dict DICT_SRCS)
aux_source_directory(src/pcore PCORE_SRCS)

set(AE_SRCS src/ae/ae.c src/ae/anet.c)
aux_source_directory(src MAIN_MSG_SRCS)
set(MAIN_SRCS src/main.c)

#  LIBS
add_library(zmalloc SHARED ${ZMALLOC_SRCS})
add_library(sds SHARED ${SDS_SRCS})
target_link_libraries(sds zmalloc)
add_library(adlist SHARED ${ADLIST_SRCS})
add_library(ae SHARED ${AE_SRCS})
add_library(cjson SHARED ${CJSON_SRCS})
add_library(dict SHARED ${DICT_SRCS})
target_link_libraries(dict zmalloc m)
set(EXT_LIBS m uv zmalloc sds ae cjson adlist dict ssl crypto)

# core
add_executable(pcore_core ${MAIN_SRCS} ${PCORE_SRCS})
target_include_directories(pcore_core PRIVATE src PRIVATE src/pcore)
target_compile_definitions(pcore_core PUBLIC -DELINK_MODE=1 -DELINK_MODE_NAME="CORE")
target_link_libraries(pcore_core ${EXT_LIBS})

# server
add_executable(pcore_server ${MAIN_MSG_SRCS} ${PCORE_SRCS})
target_include_directories(pcore_server PRIVATE src PRIVATE src/pcore)
target_compile_definitions(pcore_server PUBLIC -DELINK_MODE=1 -DELINK_MODE_NAME="SERVER" -DCONFIG_MSG)
target_link_libraries(pcore_server ${EXT_LIBS})

# client
add_executable(pcore_client ${MAIN_MSG_SRCS} ${PCORE_SRCS})
target_include_directories(pcore_client PRIVATE src PRIVATE src/pcore)
target_compile_definitions(pcore_client PUBLIC -DELINK_MODE=0 -DELINK_MODE_NAME="CLIENT" -DCONFIG_MSG)
target_link_libraries(pcore_client ${EXT_LIBS})

# test
aux_source_directory(test TEST_SRCS)
foreach(SRC ${TEST_SRCS})
    get_filename_component(OBJ ${SRC} NAME_WE)
    add_executable(${OBJ} ${SRC})
    target_link_libraries(${OBJ} ${EXT_LIBS})
endforeach(SRC ${TEST_SRCS})