cmake_minimum_required(VERSION 3.16)
project(jkit)

option(USE_HTTP2 "build with http2 support" OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message("Setting build type to 'RelWithDebInfo' as none was specified.")
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Choose the type of build." FORCE)
    #设置多种编译类型的选项
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release"
    "MinSizeRel" "RelWithDebInfo")
endif()

# http_test_client
add_executable(http_test_client
    common/logger.cpp
    http/multi_client_http.cpp
    examples/http/client_main.cpp)
target_include_directories(http_test_client PRIVATE
    http
    common
    common/fiber
    db
    third_party/include)
target_link_directories(http_test_client PRIVATE lib)
target_link_libraries(http_test_client PRIVATE
    -Wl,--start-group
    boost_log boost_fiber boost_filesystem boost_context boost_log_setup boost_thread boost_date_time boost_json
    ssl pthread crypto
    -Wl,--end-group)
target_compile_features(http_test_client PRIVATE cxx_std_17)
set_target_properties(http_test_client PROPERTIES CXX_EXTENSIONS OFF)
set_target_properties(http_test_client PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")

# http_test_server
add_executable(http_test_server
    common/logger.cpp
    http/http_api_server.cpp
    db/json2sql.cpp
    examples/http/server_main.cpp)
target_include_directories(http_test_server PRIVATE
    http
    common
    common/fiber
    db
    third_party/include)
target_link_directories(http_test_server PRIVATE lib)
target_link_libraries(http_test_server PRIVATE
    -Wl,--start-group
    boost_log boost_fiber boost_filesystem boost_context boost_log_setup boost_thread boost_date_time boost_regex boost_json
    ssl pthread crypto
    -Wl,--end-group)
target_compile_features(http_test_server PRIVATE cxx_std_17)
set_target_properties(http_test_server PROPERTIES CXX_EXTENSIONS OFF)
set_target_properties(http_test_server PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")

if(USE_HTTP2)
    # http2_test_client
    add_executable(http2_test_client
        common/logger.cpp
        http/multi_client_http.cpp
        examples/http/client2_main.cpp)
    target_compile_definitions(http2_test_client PRIVATE USE_CLIENT_HTTP2=1)
    target_include_directories(http2_test_client PRIVATE
        http
        common
        common/fiber
        db
        third_party/include)
    target_link_directories(http2_test_client PRIVATE lib)
    target_link_libraries(http2_test_client PRIVATE
        -Wl,--start-group
        boost_log boost_fiber boost_filesystem boost_context boost_log_setup boost_thread boost_date_time boost_json
        nghttp2_asio nghttp2
        ssl pthread crypto
        -Wl,--end-group)
    target_compile_features(http2_test_client PRIVATE cxx_std_17)
    set_target_properties(http2_test_client PROPERTIES CXX_EXTENSIONS OFF)

    # http2_test_server
    add_executable(http2_test_server
        examples/http/server2_main.cpp)
    target_compile_definitions(http2_test_server PRIVATE USE_CLIENT_HTTP2=1)
    target_include_directories(http2_test_server PRIVATE
        http
        common
        common/fiber
        db
        third_party/include)
    target_link_directories(http2_test_server PRIVATE lib)
    target_link_libraries(http2_test_server PRIVATE
        -Wl,--start-group
        ssl pthread crypto nghttp2_asio nghttp2
        -Wl,--end-group)
    target_compile_features(http2_test_server PRIVATE cxx_std_17)
    set_target_properties(http2_test_server PROPERTIES CXX_EXTENSIONS OFF)
endif(USE_HTTP2)



