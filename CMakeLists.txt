cmake_minimum_required(VERSION 3.10)
project(P-manager LANGUAGES C VERSION 1.0.0)

# Set the C standard to C11
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find the OpenSSL package
find_package(OpenSSL REQUIRED)
find_package(cJSON REQUIRED)

add_compile_options(-g)
# Add the include directories for OpenSSL
include_directories(${OPENSSL_INCLUDE_DIR})

# add_executable(main ${SOURCES})
add_executable(main src/main.c src/context.c src/fileHandle.c src/authHandle.c src/cryptoHandle.c src/jsonHandle.c src/vaultHandle.c )

# Link the OpenSSL crypto library
target_link_libraries(main OpenSSL::Crypto cjson)
