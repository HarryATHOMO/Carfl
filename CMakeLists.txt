cmake_minimum_required(VERSION 3.9)

set(PROJECTNAME "CarflowServer")

project(${PROJECTNAME} C CXX)

set(CMAKE_CXX_STANDARD 17)

INCLUDE(CheckCCompilerFlag)
INCLUDE(CheckCXXCompilerFlag)

set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS)
set(CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -Wall -Wextra -Werror")

include(${CMAKE_CURRENT_SOURCE_DIR}/tools/cmake/pc_linux-toolchain.cmake)

set(PRJ_INCLUDES 
   	#${INCLUDES}
	${CMAKE_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}/src/
	#${CMAKE_CURRENT_SOURCE_DIR}
	#${CMAKE_CURRENT_SOURCE_DIR}/common/libs
	#${CMAKE_INSTALL_PREFIX}/usr/include
	#${CMAKE_CURRENT_SOURCE_DIR}/common/interfaces
)


set(PJR_SOURCES
    src/main.cpp
	src/RestHandlerPackage.cpp
	src/RestApiHandler/Connexion.cpp
	src/RestApiHandler/Inscription.cpp
	#src/Version.cpp
	#src/server/Server.cpp
	#src/server/ServiceServer.cpp
	#src/aws/AWSManager.cpp
	#src/aws/ServiceAWS.cpp
	#src/mqtt/MQTTManager.cpp
	#src/mqtt/ServiceMqtt.cpp
	#src/db/Db.cpp
	#src/db/Procedures.cpp
	#src/Setup.cpp
	#src/Version.cpp
	#${CMAKE_CURRENT_SOURCE_DIR}/common/Secure/Secure.cpp
	#${CMAKE_CURRENT_SOURCE_DIR}/common/utils/utils.cpp
	#${CMAKE_CURRENT_SOURCE_DIR}/common/utils/FilesystemUtils.cpp
	#${CMAKE_CURRENT_SOURCE_DIR}/common/utils/InterfacesUtils.cpp
	#${CMAKE_CURRENT_SOURCE_DIR}/common/message/Messenger.cpp
)

#add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/libs/bcrypt)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/Common/Exceptions)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/Common/Utils)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/Common/Network)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/Common/Package)
#add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/Common/Configuration)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/Common/Logger)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/Common/Component)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/Common/Database)



include_directories(${PRJ_INCLUDES} ${INCLUDES})

#link_directories(${LINK_DIRECTORIES} ${LD_DIRS} ${CMAKE_INSTALL_PREFIX}/usr/lib ${CMAKE_INSTALL_DIR}/usr/lib ${CMAKE_INSTALL_PREFIX}/usr/lib64 ${CMAKE_CURRENT_SOURCE_DIR}/tools/usr/local/lib)
add_executable(${PROJECTNAME} ${PJR_SOURCES})
#target_link_libraries(${PROJECTNAME} ${LD_FLAGS} )
#target_link_libraries(${PROJECTNAME} -lcpprest -lboost_system -ldl -lm bcrypt ${YIP_GTEST_LIB} sqlite3 exceptions utils logger)

target_link_libraries(${PROJECTNAME} -lpthread -lssl -lcrypto -lstdc++fs -ljsoncpp  logger comp packageComponent db pqxx pq  utils exceptions network -lInfluxDB)