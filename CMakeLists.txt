cmake_minimum_required(VERSION 3.10)
project(P-manager C)

# Set the C standard to C11
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find the OpenSSL package
find_package(OpenSSL REQUIRED)
find_package(cJSON REQUIRED)

# Add the include directories for OpenSSL
include_directories(${OPENSSL_INCLUDE_DIR})

# # Specify the source files
# set(SOURCES
#     ${PROJECT_SOURCE_DIR}/src/main.c
#     ${PROJECT_SOURCE_DIR}/src/context.c
#     ${PROJECT_SOURCE_DIR}/src/authHandle.c
#     ${PROJECT_SOURCE_DIR}/src/jsonHandle.c
# )
#
# # Add the executable target
# add_executable(main ${SOURCES})
add_executable(testJson test/jsonTest.c src/jsonHandle.c)
add_executable(main src/main.c src/context.c src/fileHandle.c src/authHandle.c src/cryptoHandle.c)

# Link the OpenSSL crypto library
target_link_libraries(testJson PRIVATE cjson)
target_link_libraries(main OpenSSL::Crypto)
