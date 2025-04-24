set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
CMAKE_MINIMUM_REQUIRED(VERSION 3.31)
project(des LANGUAGES C CXX)
set(CMAKE_CXX_COMPILER g++)
set(CMAKE_C_COMPILER gcc)
set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Debug)


include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
set(SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/src/des_key.cxx
  ${CMAKE_CURRENT_SOURCE_DIR}/src/des.cxx
)

add_library(${PROJECT_NAME} ${SOURCES})
target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra)

add_executable(bin.out ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cxx)
target_link_libraries(bin.out ${PROJECT_NAME})

target_compile_options(bin.out PRIVATE -Wall -Wextra)
