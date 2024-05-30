cmake_minimum_required(VERSION 3.13.4)

set(PRJ_TEST_NAME CarflowServerUT)

project(${PRJ_TEST_NAME} LANGUAGES CXX VERSION 1.0.0)

include(GoogleTest)

set(PRJ_INCLUDES 
   	#${INCLUDES}
	${CMAKE_SOURCE_DIR}/../src
	${CMAKE_CURRENT_SOURCE_DIR}
	#${CMAKE_CURRENT_SOURCE_DIR}
	#${CMAKE_CURRENT_SOURCE_DIR}/common/libs
	#${CMAKE_INSTALL_PREFIX}/usr/include
	#${CMAKE_CURRENT_SOURCE_DIR}/common/interfaces
)

set(UT_HDRS
    ${CMAKE_CURRENT_SOURCE_DIR}/..
	${CMAKE_CURRENT_SOURCE_DIR}/..
	${CMAKE_SOURCE_DIR})

set(UT_SRCS
    ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/RestApiHandler/InscriptionTest.cpp
)

set(SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/RestApiHandler/Inscription.cpp
)

include_directories(${UT_HDRS})

set(COMMON_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../..)


add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../Common/Network network)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../Common/Utils utils)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../Common/Exceptions exception)
#add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../Common/Network)
#add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../Common/Package)
#add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/Common/Configuration)
#add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../Common/Logger)
#add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../Common/Component)
#add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../Common/Database)


message(${PRJ_INCLUDES})
include_directories(${UT_HDRS} ${PRJ_INCLUDES})


message(${UT_HDRS})

add_executable(${PRJ_TEST_NAME})

target_sources(${PRJ_TEST_NAME} PRIVATE ${UT_SRCS} ${SRC})

target_link_libraries(${PRJ_TEST_NAME}  -lgtest -lgtest_main -lpthread -ljsoncpp -lcpr -lInfluxDB pqxx pq)

target_link_libraries(${PRJ_TEST_NAME} network utils exceptions)
#-lpthread -lssl -lcrypto -lstdc++fs -ljsoncpp -lcpr  logger comp packageComponent db pqxx pq  utils exceptions network -lInfluxDB