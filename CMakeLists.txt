cmake_minimum_required(VERSION 3.5)
project(RedSASL CXX)

include(GNUInstallDirs)

set(RedSASL_VERSION_MAJOR 0)
set(RedSASL_VERSION_MINOR 0)
set(RedSASL_VERSION_PATCH 0)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wno-unused-parameter -finput-charset=UTF-8 -fexec-charset=UTF-8")

find_package(OpenSSL REQUIRED)
include_directories(OPENSSL_INCLUDE_DIR)

add_library(redsasl STATIC redsasl.cpp redsasl.hpp)
target_link_libraries(redsasl ${OPENSSL_LIBRARIES})

install(TARGETS redsasl DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES redsasl.hpp DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
