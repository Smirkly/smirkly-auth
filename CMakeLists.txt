cmake_minimum_required(VERSION 3.12...3.31)
project(smirkly-auth CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(DownloadUserver)

set(USERVER_PYTHON "/opt/homebrew/bin/python3.12"
        CACHE FILEPATH "Python for userver venvs")

set(USERVER_FEATURE_REDIS ON)
set(USERVER_FEATURE_POSTGRESQL ON)
set(USERVER_FEATURE_PATCH_LIBPQ OFF)

find_package(
        userver
        COMPONENTS core postgresql redis
        QUIET
)
if (NOT userver_FOUND)
    # Tries TRY_DIR first, falls back to downloading userver from GitHub using CPM.
    download_userver(TRY_DIR third_party/userver)
endif ()

userver_setup_environment()

# SQL library

userver_add_sql_library(
        ${PROJECT_NAME}_sql
        NAMESPACE
        smirkly::auth
        SOURCE_DIR
        ${CMAKE_CURRENT_SOURCE_DIR}/sql/auth
        OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}
        SQL_FILES
        read/devices/*.sql
        read/sessions/*.sql
        read/users/*.sql
        write/devices/*.sql
        write/email_outbox/*.sql
        write/sessions/*.sql
        write/users/*.sql
)

# include submodules
add_subdirectory(third_party/libbcrypt)
include_directories(third_party/libbcrypt/include)

# Common sources
include_directories(src)

file(GLOB_RECURSE PROJECT_SOURCES CONFIGURE_DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp
)
list(REMOVE_ITEM PROJECT_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp)

add_library(
        ${PROJECT_NAME}_objs OBJECT
        ${PROJECT_SOURCES}
)
target_link_libraries(
        ${PROJECT_NAME}_objs
        PUBLIC
        userver::core
        userver::postgresql
        ${PROJECT_NAME}_sql
        userver::redis
        bcrypt
)


# The Service
add_executable(${PROJECT_NAME} src/main.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE
        ${PROJECT_NAME}_objs
)

# Unit Testsll
file(GLOB_RECURSE PROJECT_TEST_SOURCES CONFIGURE_DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/*.cpp
)
if (PROJECT_TEST_SOURCES)
    add_executable(${PROJECT_NAME}_unittest ${PROJECT_TEST_SOURCES})

    target_link_libraries(${PROJECT_NAME}_unittest
            PRIVATE
            ${PROJECT_NAME}_objs
            userver::core
            userver::utest
            userver::postgresql
            userver::redis
    )

    # userver macro that adds gtest, filters, etc.
    add_google_tests(${PROJECT_NAME}_unittest)
endif ()

# Benchmarks
file(GLOB_RECURSE PROJECT_BENCH_SOURCES CONFIGURE_DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/*.cpp
)
if (PROJECT_BENCH_SOURCES)
    add_executable(${PROJECT_NAME}_benchmark ${PROJECT_BENCH_SOURCES})
    target_link_libraries(${PROJECT_NAME}_benchmark PRIVATE ${PROJECT_NAME}_objs userver::ubench)
    add_google_benchmark_tests(${PROJECT_NAME}_benchmark)
endif ()

# Functional testing
option(SMIRKLY_AUTH_ENABLE_TESTSUITE "Enable userver testsuite target" OFF)

if (SMIRKLY_AUTH_ENABLE_TESTSUITE)
    userver_testsuite_add_simple(
            SERVICE_TARGET ${PROJECT_NAME}
            SQL_LIBRARY ${PROJECT_NAME}_sql
    )
endif ()


# Install
include(GNUInstallDirs)

if (DEFINED ENV{PREFIX})
    message(STATUS "Set install prefix: $ENV{PREFIX}")
    file(TO_CMAKE_PATH "$ENV{PREFIX}" PREFIX_PATH)
    set(CMAKE_INSTALL_PREFIX "${PREFIX_PATH}")
endif ()

file(GLOB CONFIGS_FILES ${CMAKE_CURRENT_SOURCE_DIR}/configs/*.yaml ${CMAKE_CURRENT_SOURCE_DIR}/configs/*.json)

install(
        TARGETS ${PROJECT_NAME}
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT ${PROJECT_NAME}
)
install(
        FILES ${CONFIGS_FILES}
        DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/${PROJECT_NAME}
        COMPONENT ${PROJECT_NAME}
)
