#ifndef MULTI_CLIENT_HTTP_HPP
#define MULTI_CLIENT_HTTP_HPP

#include <string>
#include <thread>
#include <mutex>
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
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/fiber/all.hpp>

#ifdef USE_CLIENT_HTTP2
#include "nghttp2/asio_http2_client.h"
#endif

#include "logger.h"
#include "fiber/yield.hpp"

namespace http = boost::beast::http;
namespace ssl = boost::asio::ssl;
namespace asio = boost::asio;

using boost::posix_time::ptime;
using boost::beast::tcp_stream;
using std::string;
using std::list;
using std::map;

typedef boost::asio::io_context IoContext;
typedef boost::asio::ip::tcp::acceptor Acceptor;
typedef boost::asio::ip::tcp::endpoint Endpoint;
typedef boost::asio::ip::tcp::socket TcpSocket;
typedef boost::asio::ip::tcp::resolver Resolver;
typedef boost::asio::ip::tcp::resolver::results_type ResolverResult;
typedef boost::asio::executor_work_guard<boost::asio::io_context::executor_type> IoContextWork;
typedef boost::asio::ssl::context SslContext;

typedef boost::system::error_code BSError;


typedef http::request<http::string_body> StrRequest;
typedef http::response<http::string_body> StrResponse;

struct HttpReqArgument
{
    string host;
    string port;
    int dns_timeout = 5;
    int conn_timeout = 3;
    int req_timeout = 6;
};

struct HttpsReqArgument : public HttpReqArgument
{
    int handshake_timeout = 3;
    string ssl_cert; //如果为空,表示不确认
};

class MultiClientHttp
{
public:
    //必须先初始化
    static void init();

    //http请求
    static StrResponse h1_req(const StrRequest &req, const HttpReqArgument& args) noexcept;

    //https请求
    static StrResponse h1_req(const StrRequest &req, const HttpsReqArgument& args) noexcept;

    //双向确认 没有实现

#ifdef USE_CLIENT_HTTP2
    static StrResponse h2_req(const StrRequest &req, const HttpsReqArgument& args) noexcept;
#endif //USE_CLIENT_HTTP2
};

#endif /* MULTI_CLIENT_HTTP_HPP */
