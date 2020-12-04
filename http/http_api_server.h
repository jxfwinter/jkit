#ifndef HTTP_API_SERVER_H
#define HTTP_API_SERVER_H

#include <boost/beast.hpp>
#include <boost/regex.hpp>
#include <boost/asio.hpp>
#include <boost/fiber/all.hpp>

#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <map>
#include <cstdio>
#include <cctype>
#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include <functional>

#include "fiber/yield.hpp"
#include "logger.h"
#include "web_utility.hpp"

namespace http = boost::beast::http;
namespace asio = boost::asio;

typedef boost::asio::io_context IoContext;
typedef boost::asio::ip::tcp::acceptor Acceptor;
typedef boost::asio::ip::tcp::endpoint Endpoint;
typedef boost::asio::ip::tcp::socket TcpSocket;
typedef boost::asio::executor_work_guard<boost::asio::io_context::executor_type> IoContextWork;

typedef boost::system::error_code BSError;

typedef http::request<http::string_body> StrRequest;
typedef http::response<http::string_body> StrResponse;
typedef int socket_type;

using std::string;
using boost::beast::tcp_stream;

struct HttpContext
{
    boost::asio::ip::tcp::endpoint remote_endpoint;
    string path; //不包含问号后参数
    boost::smatch path_params;
    CaseInsensitiveMultimap query_params;

    StrRequest req;
    StrResponse res;
};

class HttpApiServer
{
public:
    HttpApiServer(int thread_count, const std::string &listen_address, uint16_t listen_port);
    virtual ~HttpApiServer();

    void start();
    void stop();

protected:
    //最早预处理cxt
    virtual void first_process(HttpContext& cxt) {}

    //最后统一处理cxt,主要用于设置http响应头,或打印日志
    virtual void last_process(HttpContext& cxt) {}

private:
    class RegexOrderable : public boost::regex
    {
        std::string str;

    public:
        RegexOrderable(const char *regex_cstr) : boost::regex(regex_cstr), str(regex_cstr) {}
        RegexOrderable(std::string regex_str) : boost::regex(regex_str), str(std::move(regex_str)) {}
        bool operator<(const RegexOrderable &rhs) const noexcept
        {
            return str < rhs.str;
        }
    };

protected:
    typedef std::function<void(HttpContext &)> ResourceCall;
    std::map<RegexOrderable, std::map<http::verb, ResourceCall>> m_resource;
    ResourceCall m_default_resource;
    std::function<void(HttpContext &, const string &)> m_bad_resource;

    uint16_t m_timeout = 0;
    uint64_t m_body_limit = 0;

private:
    void handle_request(HttpContext &cxt);

    //返回false表示没找到资源函数
    bool call_resource(HttpContext &cxt);

    //每个连接一个session
    void session(tcp_stream &stream);

    void accept();

private:
    int m_thread_count = 1;
    boost::asio::io_context m_io_cxt;
    std::unique_ptr<IoContextWork> m_work;
    Acceptor m_acceptor;
    std::vector<std::thread> m_threads;

    boost::fibers::fiber m_accept_fiber;
    Endpoint m_listen_ep;
    boost::fibers::mutex m_session_mutex;
    int m_session_number = 0;
    boost::fibers::condition_variable_any m_session_cnd;
    std::atomic_bool m_running;
};

#endif
