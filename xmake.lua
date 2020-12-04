option("http2")
    add_defines("USE_CLIENT_HTTP2")
    add_links("nghttp2_asio", "nghttp2")
option_end()

target("http_test_client")
    set_kind("binary")
    add_includedirs(
        "./http",
        "./common",
        "./common/fiber",
        "./third_party/include"
    )
    add_linkdirs(
        "./lib"
    )

    add_links(
        "boost_log",
        "boost_fiber",
        "boost_filesystem",
        "boost_context",
        "boost_log_setup",
        "boost_thread",
        "boost_date_time",
        "ssl",
        "pthread",
        "crypto"
    )

    add_options("http2")

    add_files(
        "./common/logger.cpp",
        "./http/multi_client_http.cpp",
        "./examples/http/client_main.cpp"
    )
target_end()

target("http_test_server")
    set_kind("binary")
    add_includedirs(
        "./http",
        "./common",
        "./common/fiber",
        "./third_party/include"
    )
    add_linkdirs(
        "./lib"
    )

    add_links(
        "boost_log",
        "boost_fiber",
        "boost_filesystem",
        "boost_context",
        "boost_log_setup",
        "boost_thread",
        "boost_date_time",
        "boost_regex",
        "ssl",
        "pthread",
        "crypto"
    )

    add_files(
        "./common/logger.cpp",
        "./http/http_api_server.cpp",
        "./examples/http/server_main.cpp"
    )
target_end()

if has_config("http2") then
    target("http2_test_client") {


        add_files(
            "./common/logger.cpp",
            "./http/multi_client_http.cpp",
            "./examples/http/client2_main.cpp"
        )

        add_options("http2")
        add_links(
            "boost_log",
            "boost_fiber",
            "boost_filesystem",
            "boost_context",
            "boost_log_setup",
            "boost_thread",
            "boost_date_time",
            "ssl",
            "pthread",
            "crypto"
        )
    }
end

executable("http2_test_server") {
    if has_config("http2") then
        set_enabled(false)
    end

    add_files(
        "./examples/http/server2_main.cpp"
    )
    add_links("ssl", "pthread", "crypto")
}
