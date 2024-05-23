cmake_minimum_required(VERSION 3.13.4)

set(PRJ_TEST_NAME CarflowServerUT)

set(UT_HDRS
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
	${CMAKE_CURRENT_SOURCE_DIR}/..
	${CMAKE_SOURCE_DIR})

set(UT_SRCS
    ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Network/Http/RestApiParserTest.cpp
)

set(COMMON_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../..)


add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../Network/Http http)
target_include_directories(http PRIVATE ${COMMON_PATH})

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../Utils utils)
target_include_directories(utils PRIVATE ${COMMON_PATH})


include_directories(${UT_HDRS})

include(GoogleTest)

message(${UT_HDRS})

add_executable(${PRJ_TEST_NAME})

target_sources(${PRJ_TEST_NAME} PRIVATE ${UT_SRCS})

target_link_libraries(${PRJ_TEST_NAME}  -lgtest -lgtest_main -lpthread)

target_link_libraries(${PRJ_TEST_NAME}  http utils)