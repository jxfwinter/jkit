# jkit

#### 介绍
常用库

#### 版本
1.  boost 1.72
2.  nghttp2 1.40
3.  jwt
4.  backtrace
5.  nghttp2 1.40
6.  nlohmann/json 3.7.3


#### 编译说明

1.  不使用http2协议 gn gen out/release --args="is_debug=false has_http2=false"
2.  使用http2协议 gn gen out/release --args="is_debug=false has_http2=true"
3.  编译所有 ninja -C out/release
3.  编译单个 ninja -C out/release http_test_client 或 http_test_server http2_test_client http2_test_server

