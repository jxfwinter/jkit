#ifndef MULTI_CLIENT_HTTP_HPP
#define MULTI_CLIENT_HTTP_HPP

#include <string>
#include <thread>
#include <list>
#include <map>
#include <memory>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include "logger.h"

using std::string;
using std::list;
using std::map;

typedef http::request<http::string_body> StrRequest;
typedef http::response<http::string_body> StrResponse;

struct HttpReqArgument
{
    string host;
    string port;
    int dns_timeout = 5;
    int conn_timeout = 3;
    int req_timeout = 6;
}

struct HttpsReqArgument : public HttpReqArgument
{
    int handshake_timeout = 3;
    string ssl_cert; //如果为空,表示不确认
}

class MultiClientHttp
{
public:
    MultiClientHttp(int thread_count = 1);
    ~MultiClientHttp();

    //http请求
    StrResponse h1_req(const StrRequest &req, const HttpReqArgument& args) noexcept;

    //https请求
    StrResponse h1_req(const StrRequest &req, const HttpsReqArgument& args) noexcept;

    //双向确认 没有实现

#ifdef USE_CLIENT_HTTP2

#endif //USE_CLIENT_HTTP2

protected:
    int m_thread_count = 1;
    boost::asio::io_context m_io_cxt;
    typedef boost::asio::executor_work_guard<boost::asio::io_context::executor_type> io_context_work;
    std::unique_ptr<io_context_work> m_work;
    std::vector<std::thread> m_threads;

    boost::fibers::condition_variable_any m_stop_cnd;
    boost::fibers::mutex m_stop_mux;
    boost::fibers::fiber m_timer_fiber;
    bool m_running = true;
};

#endif /* MULTI_CLIENT_HTTP_HPP */
