include_guard(GLOBAL)

function(download_libcurl)
    set(OPTIONS)
    set(ONE_VALUE_ARGS TRY_DIR VERSION GIT_TAG)
    set(MULTI_VALUE_ARGS)
    cmake_parse_arguments(ARG "${OPTIONS}" "${ONE_VALUE_ARGS}" "${MULTI_VALUE_ARGS}" ${ARGN})

    if(ARG_TRY_DIR)
        get_filename_component(ARG_TRY_DIR "${ARG_TRY_DIR}" REALPATH)
        if(EXISTS "${ARG_TRY_DIR}")
            message(STATUS "Using libcurl from ${ARG_TRY_DIR}")
            add_subdirectory("${ARG_TRY_DIR}" third_party/curl)
            return()
        endif()
    endif()

    cmake_minimum_required(VERSION 3.21)
    include(get_cpm)

    if(NOT DEFINED ARG_VERSION AND NOT DEFINED ARG_GIT_TAG)
        set(ARG_GIT_TAG curl-8_7_1)
    endif()

    if(NOT DEFINED CPM_USE_NAMED_CACHE_DIRECTORIES)
        set(CPM_USE_NAMED_CACHE_DIRECTORIES ON)
    endif()

    set(BUILD_CURL_EXE OFF CACHE BOOL "" FORCE)
    set(BUILD_TESTING OFF CACHE BOOL "" FORCE)

    set(CURL_DISABLE_LDAP ON CACHE BOOL "" FORCE)
    set(CURL_DISABLE_LDAPS ON CACHE BOOL "" FORCE)
    set(CURL_DISABLE_RTSP ON CACHE BOOL "" FORCE)
    set(CURL_DISABLE_TELNET ON CACHE BOOL "" FORCE)
    set(CURL_DISABLE_DICT ON CACHE BOOL "" FORCE)
    set(CURL_DISABLE_FILE ON CACHE BOOL "" FORCE)
    set(CURL_DISABLE_TFTP ON CACHE BOOL "" FORCE)
    set(CURL_DISABLE_GOPHER ON CACHE BOOL "" FORCE)
    set(CURL_DISABLE_MQTT ON CACHE BOOL "" FORCE)

    set(CURL_DISABLE_SMTP OFF CACHE BOOL "" FORCE)

    cpmaddpackage(
            NAME
            curl
            GITHUB_REPOSITORY
            curl/curl
            VERSION
            ${ARG_VERSION}
            GIT_TAG
            ${ARG_GIT_TAG}
            ${ARG_UNPARSED_ARGUMENTS}
    )

    if(TARGET libcurl AND NOT TARGET CURL::libcurl)
        add_library(CURL::libcurl ALIAS libcurl)
    endif()
endfunction()
