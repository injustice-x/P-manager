cmake_minimum_required(VERSION 3.10)
project(P-manager C)

# Set the C standard to C11
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find the OpenSSL package
find_package(OpenSSL REQUIRED)

# Add the include directories for OpenSSL
include_directories(${OPENSSL_INCLUDE_DIR})

# Specify the source files
set(SOURCES
    ${PROJECT_SOURCE_DIR}/src/main.c
    ${PROJECT_SOURCE_DIR}/src/addUser.c
    ${PROJECT_SOURCE_DIR}/src/context.c
    ${PROJECT_SOURCE_DIR}/src/hashIt.c
)

# Add the executable target
add_executable(main ${SOURCES})

# Link the OpenSSL crypto library
target_link_libraries(main OpenSSL::Crypto)
