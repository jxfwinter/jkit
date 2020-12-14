# jkit

#### 介绍
常用库

#### 版本
1.  boost 1.75
2.  nghttp2 1.40
3.  jwt
4.  backtrace
5.  soci 4.0.1


#### 编译说明

1.  不使用http2协议 cmake -S . -B build
2.  使用http2协议 cmake -S . -B build -D USE_HTTP2=ON
3.  编译所有 cmake --build build -j 1 -v
3.  编译单个 cmake --build build -j 1 -v -t http_test_client 或 cmake --build build -j 1 -v -t http2_test_server

