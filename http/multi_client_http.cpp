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

struct HttpConnection
{
    HttpReqArgument args
        tcp_stream stream;
    bool in_use = false;
    ptime last_use;
};

typedef std::shared_ptr<HttpConnection> HttpConnectionPtr;

struct HttpsConnection
{
    HttpsReqArgument args;
    ssl::stream<tcp_stream> stream;
    bool in_use = false;
    ptime last_use;
};

typedef std::shared_ptr<HttpsConnection> HttpsConnectionPtr;

class HttpCache
{
public:
    bool resolve(const string &host, const string &port, int timeout, ResolverResult &rr) noexcept
    {
        boost::fibers::future<BSError> f;
        BSError ec;
        boost::fibers::future_status fs;

        tcp::resolver resolver(m_io_cxt);
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
            LogErrorExt <<  ec.message();
            return false;
        }
        return true;
    }

    bool connect(tcp::socket &socket, const ResolverResult &rr, int timeout) noexcept
    {
        boost::fibers::future<BSError> f;
        BSError ec;
        boost::fibers::future_status fs;
        f = socket.async_connect(*rr.begin(), boost::asio::fibers::use_future([](const BSError &ec) {
            return ec;
        }));
        fs = f.wait_for(std::chrono::seconds(timeout));
        if (fs == boost::fibers::future_status::timeout)
        {
            log_error_ext("connect timeout");
            return false;
        }
        ec = f.get();
        if (ec)
        {
            log_error_ext(ec.message());
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
                log_error_ext(ec.message());
                return false;
            }
        }
        else
        {
            ctx.set_verify_mode(ssl::verify_none);
        }
        return true;
    }

    HttpConnectionPtr get_http_connect(const string &host, const string &port) noexcept
    {
        {
            std::lock_guard<boost::fibers::mutex> lk{m_http_mutex};
            for (auto it = m_cache_http_conns.begin(); it != m_cache_http_conns.end(); ++it)
            {
                HttpConnectionPtr &ptr = *it;
                if (!ptr->in_use && ptr->host == host && ptr->port == port)
                {
                    ptr->in_use = true;
                    ptr->last_use = boost::posix_time::second_clock::local_time();
                    return ptr;
                }
            }
        }

        HttpConnectionPtr conn_ptr(new HttpConnection());
        HttpConnection &conn = *conn_ptr;

        conn.host = host;
        conn.port = port;

        //dns查询
        ResolverResult rr;
        if (!resolve(conn.host, conn.port, conn.dns_timeout, rr))
        {
            return nullptr;
        }

        std::shared_ptr<tcp::socket> socket_ptr = std::make_shared<tcp::socket>(m_io_cxt);
        conn.socket_ptr = socket_ptr;

        //连接
        if (!connect(*socket_ptr, rr, conn.conn_timeout))
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

    HttpsConnectionPtr get_https_connect(const string &host, const string &port, boost::asio::ssl::context::method ssl_method,
                                         const string &cert) noexcept
    {
        {
            std::lock_guard<boost::fibers::mutex> lk{m_https_mutex};
            for (auto it = m_cache_https_streams.begin(); it != m_cache_https_streams.end(); ++it)
            {
                HttpsConnectionPtr &ptr = *it;
                if (!ptr->in_use && ptr->host == host && ptr->port == port)
                {
                    ptr->in_use = true;
                    ptr->last_use = boost::posix_time::second_clock::local_time();
                    return ptr;
                }
            }
        }

        HttpsConnectionPtr conn_ptr(new HttpsConnection());
        HttpsConnection &conn = *conn_ptr;

        conn.host = host;
        conn.port = port;

        ssl::context ctx{ssl_method};
        if (!set_ssl(ctx, cert))
        {
            return nullptr;
        }

        //dns查询
        ResolverResult rr;
        if (!resolve(conn.host, conn.port, conn.dns_timeout, rr))
        {
            return nullptr;
        }

        std::shared_ptr<ssl::stream<tcp::socket>> stream_ptr = std::make_shared<ssl::stream<tcp::socket>>(m_io_cxt, ctx);
        ssl::stream<tcp::socket> &stream = *stream_ptr;
        conn.stream_ptr = stream_ptr;

        //设置ssl
        if (!SSL_set_tlsext_host_name(stream.native_handle(), conn.host.c_str()))
        {
            log_error_ext("SSL_set_tlsext_host_name failed");
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
        boost::fibers::future_status fs;
        f = stream.async_handshake(ssl::stream_base::client, boost::asio::fibers::use_future([](const BSError &ec) {
                                       return ec;
                                   }));
        fs = f.wait_for(std::chrono::seconds(conn.handshake_timeout));
        if (fs == boost::fibers::future_status::timeout)
        {
            log_error_ext("handshake timeout");
            return nullptr;
        }
        ec = f.get();
        if (ec)
        {
            log_error_ext(ec.message());
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
    boost::fibers::mutex m_http_mutex;
    list<HttpConnectionPtr> m_cache_http_conns;

    boost::fibers::mutex m_https_mutex;
    list<HttpsConnectionPtr> m_cache_https_streams;

    int m_unuse_timeout = 55; //超过55秒没有使用就断掉
}

static HttpCache cache;

MultiClientHttp::MultiClientHttp(int thread_count) : m_thread_count(thread_count), m_work(new io_context_work(m_io_cxt.get_executor()))
{
    boost::fibers::fiber f([this]() {
        while (1)
        {
            delete_timeout_http_connect();
            delete_timeout_https_connect();
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

string MultiClientHttp::request(const string &host, const string &port, boost::beast::http::verb method, const string &target, const string &body) noexcept
{
    StrRequest req{method, target, 11};
    req.set(http::field::host, host);
    req.content_length(body.size());
    req.body() = body;
    StrResponse res = request(host, port, req);
    return res.body();
}

StrResponse MultiClientHttp::request(const string &host, const string &port, const StrRequest &req) noexcept
{
    HttpConnectionPtr conn_ptr = get_http_connect(host, port);
    if (!conn_ptr)
    {
        StrResponse res;
        res.result(http::status::network_connect_timeout_error);
        return std::move(res);
    }
    tcp::socket &socket = *(conn_ptr->socket_ptr);

    boost::fibers::future<BSError> f;
    BSError ec;
    boost::fibers::future_status fs;

    //发送请求
    f = http::async_write(socket, req, boost::asio::fibers::use_future([](const BSError &ec, size_t) {
                              return ec;
                          }));
    ec = f.get();
    if (ec)
    {
        log_error_ext(ec.message());
        StrResponse res;
        res.result(http::status::connection_closed_without_response);
        delete_invalid_http_connect(conn_ptr);
        return std::move(res);
    }

    //返回响应
    boost::beast::flat_buffer b;
    StrResponse res;
    f = http::async_read(socket, b, res, boost::asio::fibers::use_future([](const BSError &ec, size_t) {
                             return ec;
                         }));
    fs = f.wait_for(std::chrono::seconds(conn_ptr->req_timeout));
    if (fs == boost::fibers::future_status::timeout)
    {
        log_error_ext("req timeout");
        StrResponse res;
        res.result(http::status::request_timeout);
        delete_invalid_http_connect(conn_ptr);
        return std::move(res);
    }
    ec = f.get();
    if (ec)
    {
        log_error_ext(ec.message());
        StrResponse res;
        res.result(http::status::connection_closed_without_response);
        delete_invalid_http_connect(conn_ptr);
        return std::move(res);
    }

    if (res.need_eof())
    {
        boost::system::error_code ec;
        socket.shutdown(tcp::socket::shutdown_both, ec);
        delete_invalid_http_connect(conn_ptr);
    }
    else
    {
        release_http_connect(conn_ptr);
    }
    return std::move(res);
}

string MultiClientHttp::request(const string &host, const std::string &port, boost::asio::ssl::context_base::method ssl_method, const string &cert,
                                http::verb method, const string &target, const string &body) noexcept
{
    StrRequest req{method, target, 11};
    req.set(http::field::host, host);
    req.content_length(body.size());
    req.body() = body;
    StrResponse res = request(host, port, ssl_method, cert, req);
    return res.body();
}

StrResponse MultiClientHttp::request(const string &host, const string &port, boost::asio::ssl::context::method ssl_method, StrRequest &req) noexcept
{
    return request(host, port, ssl_method, "", req);
}

StrResponse MultiClientHttp::request(const string &host, const string &port, boost::asio::ssl::context::method ssl_method, const string &cert, StrRequest &req) noexcept
{
    HttpsConnectionPtr conn_ptr = get_https_connect(host, port, ssl_method, cert);
    if (!conn_ptr)
    {
        StrResponse res;
        res.result(http::status::network_connect_timeout_error);
        return std::move(res);
    }
    ssl::stream<tcp::socket> &stream = *(conn_ptr->stream_ptr);
    boost::fibers::future<BSError> f;
    BSError ec;
    boost::fibers::future_status fs;

    //发送请求
    f = http::async_write(stream, req, boost::asio::fibers::use_future([](const BSError &ec, size_t) {
                              return ec;
                          }));
    ec = f.get();
    if (ec)
    {
        log_error_ext(ec.message());
        StrResponse res;
        res.result(http::status::connection_closed_without_response);
        delete_invalid_https_connect(conn_ptr);
        return std::move(res);
    }
    //返回响应
    boost::beast::flat_buffer b;
    StrResponse res;
    f = http::async_read(stream, b, res, boost::asio::fibers::use_future([](const BSError &ec, size_t) {
                             return ec;
                         }));
    fs = f.wait_for(std::chrono::seconds(conn_ptr->req_timeout));
    if (fs == boost::fibers::future_status::timeout)
    {
        log_error_ext("req timeout");
        StrResponse res;
        res.result(http::status::request_timeout);
        delete_invalid_https_connect(conn_ptr);
        return std::move(res);
    }
    ec = f.get();
    if (ec)
    {
        log_error_ext(ec.message());
        StrResponse res;
        res.result(http::status::connection_closed_without_response);
        delete_invalid_https_connect(conn_ptr);
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
        delete_invalid_https_connect(conn_ptr);
    }
    else
    {
        release_https_connect(conn_ptr);
    }

    return std::move(res);
}
