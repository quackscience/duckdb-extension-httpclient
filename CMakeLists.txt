cmake_minimum_required(VERSION 3.5)

# Set extension name here
set(TARGET_NAME http_client)

# Add ZLIB definition for httplib
add_compile_definitions(CPPHTTPLIB_ZLIB_SUPPORT)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})

include_directories(src/include duckdb/third_party/httplib)

set(EXTENSION_SOURCES src/http_client_extension.cpp)

if(MINGW)
  set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()

# Build extensions
build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

# Include directories
include_directories(${OPENSSL_INCLUDE_DIR})

# Common libraries needed for both targets
set(COMMON_LIBS 
    duckdb_mbedtls 
    ${OPENSSL_LIBRARIES}
    ZLIB::ZLIB
)

# Windows-specific libraries
if(MINGW)
  set(WIN_LIBS crypt32 ws2_32 wsock32)
  list(APPEND COMMON_LIBS ${WIN_LIBS})
endif()

# Link libraries
target_link_libraries(${LOADABLE_EXTENSION_NAME} ${COMMON_LIBS})
target_link_libraries(${EXTENSION_NAME} ${COMMON_LIBS})

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
