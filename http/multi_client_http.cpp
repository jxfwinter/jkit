#include "multi_client_http.h"
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/fiber/all.hpp>

#include "common/fiber/use_fiber_future.hpp"

using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>
using namespace boost::beast;     // from <boost/beast/http.hpp>
using boost::posix_time::ptime;
namespace ssl = boost::asio::ssl;

typedef boost::asio::ip::tcp::resolver::results_type ResolverResult;
typedef boost::asio::ip::tcp::endpoint Endpoint;
typedef boost::system::error_code BSError;

namespace
{
struct Connection
{
    bool in_use = false;
    ptime last_use;
};

struct HttpConnection : public HttpReqArgument, public Connection
{
    HttpConnection(boost::asio::io_context &ioc) : stream(ioc) {}
    tcp_stream stream;
};

typedef std::shared_ptr<HttpConnection> HttpConnectionPtr;

struct HttpsConnection : public HttpsReqArgument, public Connection
{
    HttpsConnection(boost::asio::io_context &ioc) : stream(ioc) {}
    ssl::stream<tcp_stream> stream;
};

typedef std::shared_ptr<HttpsConnection> HttpsConnectionPtr;

class HttpCache
{
public:
    HttpConnectionPtr get_http_connect(const HttpReqArgument &args, boost::asio::io_context &io_cxt) noexcept
    {
        {
            std::lock_guard<boost::fibers::mutex> lk{m_http_mutex};
            for (auto it = m_cache_http_conns.begin(); it != m_cache_http_conns.end(); ++it)
            {
                HttpConnectionPtr &ptr = *it;
                if (!ptr->in_use && ptr->host == args.host && ptr->port == args.port)
                {
                    ptr->dns_timeout = args.dns_timeout;
                    ptr->conn_timeout = args.conn_timeout;
                    ptr->req_timeout = args.req_timeout;
                    ptr->in_use = true;
                    ptr->last_use = boost::posix_time::second_clock::local_time();
                    return ptr;
                }
            }
        }

        HttpConnectionPtr conn_ptr(new HttpConnection(io_cxt));
        HttpConnection &conn = *conn_ptr;

        conn.host = args.host;
        conn.port = args.port;
        conn.dns_timeout = args.dns_timeout;
        conn.conn_timeout = args.conn_timeout;
        conn.req_timeout = args.req_timeout;

        //dns查询
        ResolverResult rr;
        if (!resolve(conn.host, conn.port, conn.dns_timeout, rr, io_cxt))
        {
            return nullptr;
        }

        //连接
        if (!connect(conn.stream, rr, conn.conn_timeout))
        {
            return nullptr;
        }

        {
            conn.in_use = true;
            conn.last_use = boost::posix_time::second_clock::local_time();

            std::lock_guard<boost::fibers::mutex> lk{m_http_mutex};
            m_cache_http_conns.push_back(conn_ptr);

            return conn_ptr;
        }
    }

    void release_http_connect(HttpConnectionPtr conn_ptr) noexcept
    {
        std::lock_guard<boost::fibers::mutex> lk{m_http_mutex};
        for (auto it = m_cache_http_conns.begin(); it != m_cache_http_conns.end(); ++it)
        {
            HttpConnectionPtr &ptr = *it;
            if (ptr.get() == conn_ptr.get())
            {
                ptr->stream.expires_never();
                ptr->in_use = false;
                ptr->last_use = boost::posix_time::second_clock::local_time();
                return;
            }
        }
    }

    void delete_invalid_http_connect(HttpConnectionPtr conn_ptr) noexcept
    {
        std::lock_guard<boost::fibers::mutex> lk{m_http_mutex};
        for (auto it = m_cache_http_conns.begin(); it != m_cache_http_conns.end(); ++it)
        {
            HttpConnectionPtr &ptr = *it;
            if (ptr.get() == conn_ptr.get())
            {
                m_cache_http_conns.erase(it);
                return;
            }
        }
    }

    HttpsConnectionPtr get_https_connect(const HttpsReqArgument &args, boost::asio::io_context &io_cxt) noexcept
    {
        {
            std::lock_guard<boost::fibers::mutex> lk{m_https_mutex};
            for (auto it = m_cache_https_streams.begin(); it != m_cache_https_streams.end(); ++it)
            {
                HttpsConnectionPtr &ptr = *it;
                if (!ptr->in_use && ptr->host == host && ptr->port == port)
                {
                    ptr->dns_timeout = args.dns_timeout;
                    ptr->conn_timeout = args.conn_timeout;
                    ptr->req_timeout = args.req_timeout;
                    ptr->handshake_timeout = args.handshake_timeout;
                    ptr->ssl_cert = args.ssl_cert;
                    ptr->in_use = true;
                    ptr->last_use = boost::posix_time::second_clock::local_time();
                    return ptr;
                }
            }
        }

        HttpsConnectionPtr conn_ptr(new HttpsConnection(io_cxt));
        HttpsConnection &conn = *conn_ptr;

        conn.host = args.host;
        conn.port = args.port;
        conn.dns_timeout = args.dns_timeout;
        conn.conn_timeout = args.conn_timeout;
        conn.req_timeout = args.req_timeout;
        conn.handshake_timeout = args.handshake_timeout;
        conn.ssl_cert = args.ssl_cert;

        ssl::context ctx{boost::asio::ssl::context::method::tls_client};
        if (!set_ssl(ctx, conn.ssl_cert))
        {
            return nullptr;
        }

        //dns查询
        ResolverResult rr;
        if (!resolve(conn.host, conn.port, conn.dns_timeout, rr, io_cxt))
        {
            return nullptr;
        }

        auto &stream = conn.stream;

        //设置ssl
        if (!SSL_set_tlsext_host_name(stream.native_handle(), conn.host.c_str()))
        {
            LogErrorExt << "SSL_set_tlsext_host_name failed";
            return nullptr;
        }
        //连接
        if (!connect(stream.next_layer(), rr, conn.conn_timeout))
        {
            return nullptr;
        }

        //handshake
        boost::fibers::future<BSError> f;
        BSError ec;
        stream.expires_after(std::chrono::seconds(conn.handshake_timeout));
        f = stream.async_handshake(ssl::stream_base::client, boost::asio::fibers::use_future([](const BSError &ec) {
                                       return ec;
                                   }));
        ec = f.get();
        if (ec)
        {
            LogErrorExt << ec.message();
            return nullptr;
        }

        {
            conn.in_use = true;
            conn.last_use = boost::posix_time::second_clock::local_time();

            std::lock_guard<boost::fibers::mutex> lk{m_https_mutex};
            m_cache_https_streams.push_back(conn_ptr);
            return conn_ptr;
        }
    }

    void release_https_connect(HttpsConnectionPtr stream_ptr) noexcept
    {
        std::lock_guard<boost::fibers::mutex> lk{m_https_mutex};
        for (auto it = m_cache_https_streams.begin(); it != m_cache_https_streams.end(); ++it)
        {
            HttpsConnectionPtr &ptr = *it;
            if (ptr.get() == stream_ptr.get())
            {
                ptr->stream.expires_never();
                ptr->in_use = false;
                ptr->last_use = boost::posix_time::second_clock::local_time();
                return;
            }
        }
    }

    void delete_invalid_https_connect(HttpsConnectionPtr stream_ptr) noexcept
    {
        std::lock_guard<boost::fibers::mutex> lk{m_https_mutex};
        for (auto it = m_cache_https_streams.begin(); it != m_cache_https_streams.end(); ++it)
        {
            HttpsConnectionPtr &ptr = *it;
            if (ptr.get() == stream_ptr.get())
            {
                m_cache_https_streams.erase(it);
                return;
            }
        }
    }

    //删除长久不用的连接
    void delete_timeout_http_connect() noexcept
    {
        ptime now_pt = boost::posix_time::second_clock::local_time();
        std::lock_guard<boost::fibers::mutex> lk{m_http_mutex};
        for (auto it = m_cache_http_conns.begin(); it != m_cache_http_conns.end();)
        {
            HttpConnectionPtr &ptr = *it;
            if (!ptr->in_use)
            {
                auto diff = now_pt - ptr->last_use;
                if (diff.total_seconds() > m_unuse_timeout)
                {
                    it = m_cache_http_conns.erase(it);
                }
                else
                {
                    ++it;
                }
            }
            else
            {
                ++it;
            }
        }
    }

    void delete_timeout_https_connect() noexcept
    {
        ptime now_pt = boost::posix_time::second_clock::local_time();
        std::lock_guard<boost::fibers::mutex> lk{m_https_mutex};
        //std::cout << "https stream size:" << m_cache_https_streams.size() << std::endl;
        for (auto it = m_cache_https_streams.begin(); it != m_cache_https_streams.end();)
        {
            HttpsConnectionPtr &ptr = *it;
            if (!ptr->in_use)
            {
                auto diff = now_pt - ptr->last_use;
                if (diff.total_seconds() > m_unuse_timeout)
                {
                    it = m_cache_https_streams.erase(it);
                }
                else
                {
                    ++it;
                }
            }
            else
            {
                ++it;
            }
        }
    }

private:
    bool resolve(const string &host, const string &port, int timeout, ResolverResult &rr, boost::asio::io_context &io_cxt) noexcept
    {
        boost::fibers::future<BSError> f;
        BSError ec;
        boost::fibers::future_status fs;

        tcp::resolver resolver(io_cxt);
        f = resolver.async_resolve(host, port, boost::asio::fibers::use_future([&rr](const BSError &ec, ResolverResult results) {
                                       rr = std::move(results);
                                       return ec;
                                   }));
        fs = f.wait_for(std::chrono::seconds(timeout));
        if (fs == boost::fibers::future_status::timeout)
        {
            LogErrorExt << "dns timeout";
            return false;
        }
        ec = f.get();
        if (ec)
        {
            LogErrorExt << ec.message();
            return false;
        }
        return true;
    }

    bool connect(tcp_stream &stream, const ResolverResult &rr, int timeout) noexcept
    {
        boost::fibers::future<BSError> f;
        BSError ec;
        stream.expires_after(std::chrono::seconds(timeout));
        f = stream.async_connect(*rr.begin(), boost::asio::fibers::use_future([](const BSError &ec) {
            return ec;
        }));
        ec = f.get();
        if (ec)
        {
            LogErrorExt << ec.message();
            return false;
        }
        return true;
    }

    bool set_ssl(ssl::context &ctx, const string &cert) noexcept
    {
        BSError ec;
        if (!cert.empty())
        {
            ctx.set_verify_mode(ssl::verify_peer);
            ctx.add_certificate_authority(boost::asio::buffer(cert.data(), cert.size()), ec);
            if (ec)
            {
                LogErrorExt << ec.message();
                return false;
            }
        }
        else
        {
            ctx.set_verify_mode(ssl::verify_none);
        }
        return true;
    }

private:
    boost::fibers::mutex m_http_mutex;
    list<HttpConnectionPtr> m_cache_http_conns;

    boost::fibers::mutex m_https_mutex;
    list<HttpsConnectionPtr> m_cache_https_streams;

    int m_unuse_timeout = 55; //超过55秒没有使用就断掉
};

} //namespace

static HttpCache cache;

MultiClientHttp::MultiClientHttp(int thread_count) : m_thread_count(thread_count), m_work(new io_context_work(m_io_cxt.get_executor()))
{
    boost::fibers::fiber f([this]() {
        while (1)
        {
            cache.delete_timeout_http_connect();
            cache.delete_timeout_https_connect();
            bool stop = false;
            {
                std::unique_lock<boost::fibers::mutex> lk(m_stop_mux);
                stop = m_stop_cnd.wait_for(lk, std::chrono::seconds(30), [this]() {
                    return !m_running;
                });
            }
            if (stop)
            {
                break;
            }
        }
    });

    m_timer_fiber.swap(f);

    for (int i = 0; i < m_thread_count; ++i)
    {
        std::thread t([this]() {
            m_io_cxt.run();
        });
        m_threads.push_back(std::move(t));
    }
}

MultiClientHttp::~MultiClientHttp()
{
    {
        std::unique_lock<boost::fibers::mutex> lk(m_stop_mux);
        m_running = false;
        m_stop_cnd.notify_all();
    }

    m_io_cxt.stop();
    for (int i = 0; i < m_thread_count; ++i)
    {
        m_threads[i].join();
    }

    if (m_timer_fiber.joinable())
    {
        m_timer_fiber.join();
    }
}

StrResponse MultiClientHttp::h1_req(const StrRequest &req, const HttpReqArgument &args) noexcept
{
    HttpConnectionPtr conn_ptr = cache.get_http_connect(args, m_io_cxt);
    if (!conn_ptr)
    {
        StrResponse res;
        res.result(http::status::network_connect_timeout_error);
        return std::move(res);
    }
    tcp_stream &stream = conn_ptr->stream;
    boost::fibers::future<BSError> f;
    BSError ec;
    stream.expires_after(std::chrono::seconds(args.req_timeout));
    //发送请求
    f = http::async_write(stream, req, boost::asio::fibers::use_future([](const BSError &ec, size_t) {
                              return ec;
                          }));
    ec = f.get();
    if (ec)
    {
        LogErrorExt << ec.message();
        StrResponse res;
        if (ec == boost::beast::error::timeout)
        {
            res.result(http::status::request_timeout);
        }
        else
        {
            res.result(http::status::connection_closed_without_response);
        }

        cache.delete_invalid_http_connect(conn_ptr);
        return std::move(res);
    }
    //返回响应
    boost::beast::flat_buffer b;
    StrResponse res;
    f = http::async_read(stream, b, res, boost::asio::fibers::use_future([](const BSError &ec, size_t) {
                             return ec;
                         }));
    ec = f.get();
    if (ec)
    {
        LogErrorExt << ec.message();
        StrResponse res;
        if (ec == boost::beast::error::timeout)
        {
            res.result(http::status::request_timeout);
        }
        else
        {
            res.result(http::status::connection_closed_without_response);
        }
        cache.delete_invalid_http_connect(conn_ptr);
        return std::move(res);
    }

    if (res.need_eof())
    {
        //boost::system::error_code ec;
        //socket.shutdown(tcp::socket::shutdown_both, ec);
        stream.close();
        cache.delete_invalid_http_connect(conn_ptr);
    }
    else
    {
        cache.release_http_connect(conn_ptr);
    }
    return std::move(res);
}

StrResponse MultiClientHttp::h1_req(const StrRequest &req, const HttpsReqArgument &args) noexcept
{
    HttpsConnectionPtr conn_ptr = cache.get_https_connect(args, m_io_cxt);
    if (!conn_ptr)
    {
        StrResponse res;
        res.result(http::status::network_connect_timeout_error);
        return std::move(res);
    }
    ssl::stream<tcp_stream> &stream = conn_ptr->stream;
    boost::fibers::future<BSError> f;
    BSError ec;
    stream.expires_after(std::chrono::seconds(args.req_timeout));
    //发送请求
    f = http::async_write(stream, req, boost::asio::fibers::use_future([](const BSError &ec, size_t) {
                              return ec;
                          }));
    ec = f.get();
    if (ec)
    {
        LogErrorExt << ec.message();
        StrResponse res;
        if (ec == boost::beast::error::timeout)
        {
            res.result(http::status::request_timeout);
        }
        else
        {
            res.result(http::status::connection_closed_without_response);
        }
        cache.delete_invalid_https_connect(conn_ptr);
        return std::move(res);
    }
    //返回响应
    boost::beast::flat_buffer b;
    StrResponse res;
    f = http::async_read(stream, b, res, boost::asio::fibers::use_future([](const BSError &ec, size_t) {
                             return ec;
                         }));
    ec = f.get();
    if (ec)
    {
        LogErrorExt << ec.message();
        StrResponse res;
        if (ec == boost::beast::error::timeout)
        {
            res.result(http::status::request_timeout);
        }
        else
        {
            res.result(http::status::connection_closed_without_response);
        }
        cache.delete_invalid_https_connect(conn_ptr);
        return std::move(res);
    }
    if (res.need_eof())
    {
        f = stream.async_shutdown(boost::asio::fibers::use_future([](boost::system::error_code ec) {
            return ec;
        }));
        ec = f.get();
        if (ec == boost::asio::error::eof)
        {
            // Rationale:
            // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
            ec.assign(0, ec.category());
        }
        cache.delete_invalid_https_connect(conn_ptr);
    }
    else
    {
        cache.release_https_connect(conn_ptr);
    }
}
