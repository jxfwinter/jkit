#include "multi_client_http.h"

namespace
{
struct Connection
{
    bool in_use = false;
    ptime last_use;
};

struct HttpConnection : public HttpReqArgument, public Connection
{
    HttpConnection(IoContext &ioc) : stream(ioc) {}
    tcp_stream stream;
};

typedef std::shared_ptr<HttpConnection> HttpConnectionPtr;

struct HttpsConnection : public HttpsReqArgument, public Connection
{
    HttpsConnection(IoContext &ioc, SslContext& cxt) : stream(ioc, cxt) {}
    ssl::stream<tcp_stream> stream;
};
typedef std::shared_ptr<HttpsConnection> HttpsConnectionPtr;

#ifdef USE_CLIENT_HTTP2

struct Http2Connection : public HttpsReqArgument, public Connection
{
    Http2Connection(IoContext &ioc, SslContext& cxt, const HttpsReqArgument& args) :
        session(ioc, cxt, args.host, args.port, boost::posix_time::time_duration(0, 0, args.dns_timeout + args.conn_timeout + args.handshake_timeout)) {}
    nghttp2::asio_http2::client::session session;
};
typedef std::shared_ptr<Http2Connection> Http2ConnectionPtr;

#endif

class HttpCache
{
public:
    HttpCache(int thread_count = 1);
    ~HttpCache();

    HttpConnectionPtr get_http_connect(const HttpReqArgument &args) noexcept;
    void release_http_connect(HttpConnectionPtr conn_ptr) noexcept;
    void delete_invalid_http_connect(HttpConnectionPtr conn_ptr) noexcept;
    void delete_timeout_http_connect() noexcept;

    HttpsConnectionPtr get_https_connect(const HttpsReqArgument &args) noexcept;
    void release_https_connect(HttpsConnectionPtr stream_ptr) noexcept;
    void delete_invalid_https_connect(HttpsConnectionPtr stream_ptr) noexcept;
    void delete_timeout_https_connect() noexcept;

#ifdef USE_CLIENT_HTTP2
    Http2ConnectionPtr get_http2s_connect(const HttpsReqArgument &args) noexcept;
    void delete_invalid_http2s_connect(Http2ConnectionPtr conn_ptr) noexcept;
    void delete_timeout_http2s_connect() noexcept;
#endif

private:
    bool resolve(const string &host, const string &port, int timeout, ResolverResult &rr) noexcept;
    bool connect(tcp_stream &stream, const ResolverResult &rr, int timeout) noexcept;
    bool set_ssl(ssl::context &ctx, const string &cert) noexcept;

private:
    int m_thread_count = 1;
    IoContext m_io_cxt;
    std::unique_ptr<IoContextWork> m_work;
    std::vector<std::thread> m_threads;

    boost::fibers::mutex m_h1_mutex;
    list<HttpConnectionPtr> m_h1_conns;

    boost::fibers::mutex m_h1s_mutex;
    list<HttpsConnectionPtr> m_h1s_conns;

#ifdef USE_CLIENT_HTTP2
    boost::fibers::mutex m_h2s_mutex;
    list<Http2ConnectionPtr> m_h2s_conns;
#endif
    int m_unuse_timeout = 55; //超过55秒没有使用就断掉
};

HttpCache::HttpCache(int thread_count) : m_thread_count(thread_count), m_work(new IoContextWork(m_io_cxt.get_executor()))
{
    for (int i = 0; i < m_thread_count; ++i)
    {
        std::thread t([this]() {
            m_io_cxt.run();
        });
        m_threads.push_back(std::move(t));
    }
}

HttpCache::~HttpCache()
{
    m_io_cxt.stop();
    for (int i = 0; i < m_thread_count; ++i)
    {
        m_threads[i].join();
    }
}


HttpConnectionPtr HttpCache::get_http_connect(const HttpReqArgument &args) noexcept
{
    delete_timeout_http_connect();
    {
        std::lock_guard<boost::fibers::mutex> lk{m_h1_mutex};
        for (auto it = m_h1_conns.begin(); it != m_h1_conns.end(); ++it)
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

    HttpConnectionPtr conn_ptr(new HttpConnection(m_io_cxt));
    HttpConnection &conn = *conn_ptr;

    conn.host = args.host;
    conn.port = args.port;
    conn.dns_timeout = args.dns_timeout;
    conn.conn_timeout = args.conn_timeout;
    conn.req_timeout = args.req_timeout;

    //dns查询
    ResolverResult rr;
    if (!resolve(conn.host, conn.port, conn.dns_timeout, rr))
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

        std::lock_guard<boost::fibers::mutex> lk{m_h1_mutex};
        m_h1_conns.push_back(conn_ptr);

        return conn_ptr;
    }
}

void HttpCache::release_http_connect(HttpConnectionPtr conn_ptr) noexcept
{
    std::lock_guard<boost::fibers::mutex> lk{m_h1_mutex};
    for (auto it = m_h1_conns.begin(); it != m_h1_conns.end(); ++it)
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

void HttpCache::delete_invalid_http_connect(HttpConnectionPtr conn_ptr) noexcept
{
    std::lock_guard<boost::fibers::mutex> lk{m_h1_mutex};
    for (auto it = m_h1_conns.begin(); it != m_h1_conns.end(); ++it)
    {
        HttpConnectionPtr &ptr = *it;
        if (ptr.get() == conn_ptr.get())
        {
            m_h1_conns.erase(it);
            return;
        }
    }
}

void HttpCache::delete_timeout_http_connect() noexcept
{
    ptime now_pt = boost::posix_time::second_clock::local_time();
    std::lock_guard<boost::fibers::mutex> lk{m_h1_mutex};
    for (auto it = m_h1_conns.begin(); it != m_h1_conns.end();)
    {
        HttpConnectionPtr &ptr = *it;
        if (!ptr->in_use)
        {
            auto diff = now_pt - ptr->last_use;
            if (diff.total_seconds() > m_unuse_timeout)
            {
                it = m_h1_conns.erase(it);
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

HttpsConnectionPtr HttpCache::get_https_connect(const HttpsReqArgument &args) noexcept
{
    delete_timeout_https_connect();
    {
        std::lock_guard<boost::fibers::mutex> lk{m_h1s_mutex};
        for (auto it = m_h1s_conns.begin(); it != m_h1s_conns.end(); ++it)
        {
            HttpsConnectionPtr &ptr = *it;
            if (!ptr->in_use && ptr->host == args.host && ptr->port == args.port)
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

    ssl::context ssl_ctx{boost::asio::ssl::context::method::tls_client};
    if (!set_ssl(ssl_ctx, args.ssl_cert))
    {
        return nullptr;
    }

    HttpsConnectionPtr conn_ptr(new HttpsConnection(m_io_cxt, ssl_ctx));
    HttpsConnection &conn = *conn_ptr;

    conn.host = args.host;
    conn.port = args.port;
    conn.dns_timeout = args.dns_timeout;
    conn.conn_timeout = args.conn_timeout;
    conn.req_timeout = args.req_timeout;
    conn.handshake_timeout = args.handshake_timeout;
    conn.ssl_cert = args.ssl_cert;

    //dns查询
    ResolverResult rr;
    if (!resolve(conn.host, conn.port, conn.dns_timeout, rr))
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
    BSError ec;
    stream.next_layer().expires_after(std::chrono::seconds(conn.handshake_timeout));
    stream.async_handshake(ssl::stream_base::client, boost::fibers::asio::yield[ec]);
    if (ec)
    {
        LogErrorExt << ec.message();
        return nullptr;
    }

    {
        conn.in_use = true;
        conn.last_use = boost::posix_time::second_clock::local_time();

        std::lock_guard<boost::fibers::mutex> lk{m_h1s_mutex};
        m_h1s_conns.push_back(conn_ptr);
        return conn_ptr;
    }
}

void HttpCache::release_https_connect(HttpsConnectionPtr stream_ptr) noexcept
{
    std::lock_guard<boost::fibers::mutex> lk{m_h1s_mutex};
    for (auto it = m_h1s_conns.begin(); it != m_h1s_conns.end(); ++it)
    {
        HttpsConnectionPtr &ptr = *it;
        if (ptr.get() == stream_ptr.get())
        {
            ptr->stream.next_layer().expires_never();
            ptr->in_use = false;
            ptr->last_use = boost::posix_time::second_clock::local_time();
            return;
        }
    }
}

void HttpCache::delete_invalid_https_connect(HttpsConnectionPtr stream_ptr) noexcept
{
    std::lock_guard<boost::fibers::mutex> lk{m_h1s_mutex};
    for (auto it = m_h1s_conns.begin(); it != m_h1s_conns.end(); ++it)
    {
        HttpsConnectionPtr &ptr = *it;
        if (ptr.get() == stream_ptr.get())
        {
            m_h1s_conns.erase(it);
            return;
        }
    }
}

void HttpCache::delete_timeout_https_connect() noexcept
{
    ptime now_pt = boost::posix_time::second_clock::local_time();
    std::lock_guard<boost::fibers::mutex> lk{m_h1s_mutex};
    //std::cout << "https stream size:" << m_h1s_conns.size() << std::endl;
    for (auto it = m_h1s_conns.begin(); it != m_h1s_conns.end();)
    {
        HttpsConnectionPtr &ptr = *it;
        if (!ptr->in_use)
        {
            auto diff = now_pt - ptr->last_use;
            if (diff.total_seconds() > m_unuse_timeout)
            {
                it = m_h1s_conns.erase(it);
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

#ifdef USE_CLIENT_HTTP2
Http2ConnectionPtr HttpCache::get_http2s_connect(const HttpsReqArgument &args) noexcept
{
    {
        delete_timeout_http2s_connect();
        std::lock_guard<boost::fibers::mutex> lk{m_h2s_mutex};
        for(auto it=m_h2s_conns.begin(); it!=m_h2s_conns.end(); ++it)
        {
            Http2ConnectionPtr &ptr = *it;
            if (ptr->host == args.host && ptr->port == args.port)
            {
                ptr->dns_timeout = args.dns_timeout;
                ptr->conn_timeout = args.conn_timeout;
                ptr->req_timeout = args.req_timeout;
                ptr->handshake_timeout = args.handshake_timeout;
                ptr->ssl_cert = args.ssl_cert;
                //ptr->in_use = true; h2多路复用同一个连接,不需要in_use状态
                ptr->last_use = boost::posix_time::second_clock::local_time();
                return ptr;
            }
        }
    }

    ssl::context ssl_ctx{boost::asio::ssl::context::method::tls_client};
    if (!set_ssl(ssl_ctx, args.ssl_cert))
    {
        return nullptr;
    }
    boost::system::error_code ec;
    nghttp2::asio_http2::client::configure_tls_context(ec, ssl_ctx);
    if(ec)
    {
        LogErrorExt << ec.message();
        return nullptr;
    }

    Http2ConnectionPtr conn_ptr(new Http2Connection(m_io_cxt, ssl_ctx, args));
    Http2Connection &conn = *conn_ptr;

    conn.host = args.host;
    conn.port = args.port;
    conn.dns_timeout = args.dns_timeout;
    conn.conn_timeout = args.conn_timeout;
    conn.req_timeout = args.req_timeout;
    conn.handshake_timeout = args.handshake_timeout;
    conn.ssl_cert = args.ssl_cert;

    nghttp2::asio_http2::client::session& session = conn.session;

    std::shared_ptr<boost::fibers::promise<void>> promise(new boost::fibers::promise<void>());
    boost::fibers::future<void> future(promise->get_future());

    session.on_connect([promise](boost::asio::ip::tcp::resolver::iterator endpoint) mutable {
        promise->set_value();
    });
    session.on_error([conn_ptr, this](const boost::system::error_code &ec) {
        LogErrorExt << ec.message();
        delete_invalid_http2s_connect(conn_ptr);
    });

    boost::fibers::future_status status = future.wait_for(std::chrono::seconds(conn.dns_timeout + conn.conn_timeout + conn.handshake_timeout + 1));
    if (status == boost::fibers::future_status::timeout)
    {
        return nullptr;
    }
    future.get();
    {
        conn.in_use = true;
        conn.last_use = boost::posix_time::second_clock::local_time();

        std::lock_guard<boost::fibers::mutex> lk{m_h2s_mutex};
        m_h2s_conns.push_back(conn_ptr);
        return conn_ptr;
    }
}

void HttpCache::delete_invalid_http2s_connect(Http2ConnectionPtr conn_ptr) noexcept
{
    std::lock_guard<boost::fibers::mutex> lk{m_h2s_mutex};
    for(auto it=m_h2s_conns.begin(); it!=m_h2s_conns.end(); ++it)
    {
        Http2ConnectionPtr &ptr = *it;
        if (ptr.get() == conn_ptr.get())
        {
            m_h2s_conns.erase(it);
            return;
        }
    }
}

void HttpCache::delete_timeout_http2s_connect() noexcept
{
    ptime now_pt = boost::posix_time::second_clock::local_time();
    std::lock_guard<boost::fibers::mutex> lk{m_h2s_mutex};
    for(auto it=m_h2s_conns.begin(); it!=m_h2s_conns.end();)
    {
        Http2ConnectionPtr &ptr = *it;
        auto diff = now_pt - ptr->last_use;
        if (diff.total_seconds() > m_unuse_timeout)
        {
            it = m_h2s_conns.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

#endif

bool HttpCache::resolve(const string &host, const string &port, int timeout, ResolverResult &rr) noexcept
{
    BSError ec;
    Resolver resolver(m_io_cxt);
    rr = resolver.async_resolve(host, port, boost::fibers::asio::yield[ec]);
    if (ec)
    {
        LogErrorExt << ec.message();
        return false;
    }
    return true;
}

bool HttpCache::connect(tcp_stream &stream, const ResolverResult &rr, int timeout) noexcept
{
    BSError ec;
    stream.expires_after(std::chrono::seconds(timeout));
    stream.async_connect(*rr.begin(), boost::fibers::asio::yield[ec]);
    if (ec)
    {
        LogErrorExt << ec.message();
        return false;
    }
    return true;
}

bool HttpCache::set_ssl(ssl::context &ctx, const string &cert) noexcept
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

} //namespace

static HttpCache* cache = nullptr;

void MultiClientHttp::init()
{
    if(!cache)
    {
        cache = new HttpCache();
    }
}

StrResponse MultiClientHttp::h1_req(const StrRequest &req, const HttpReqArgument &args) noexcept
{
    StrResponse res;
    HttpConnectionPtr conn_ptr = cache->get_http_connect(args);
    if (!conn_ptr)
    {
        res.result(http::status::network_connect_timeout_error);
        return std::move(res);
    }
    tcp_stream &stream = conn_ptr->stream;
    BSError ec;
    stream.expires_after(std::chrono::seconds(args.req_timeout));
    //发送请求
    http::async_write(stream, req, boost::fibers::asio::yield[ec]);
    if (ec)
    {
        LogErrorExt << ec.message();
        if (ec == boost::beast::error::timeout)
        {
            res.result(http::status::request_timeout);
        }
        else
        {
            res.result(http::status::connection_closed_without_response);
        }

        cache->delete_invalid_http_connect(conn_ptr);
        return std::move(res);
    }
    //返回响应
    boost::beast::flat_buffer b;
    http::async_read(stream, b, res, boost::fibers::asio::yield[ec]);
    if (ec)
    {
        LogErrorExt << ec.message();
        if (ec == boost::beast::error::timeout)
        {
            res.result(http::status::request_timeout);
        }
        else
        {
            res.result(http::status::connection_closed_without_response);
        }
        cache->delete_invalid_http_connect(conn_ptr);
        return std::move(res);
    }

    if (res.need_eof())
    {
        //boost::system::error_code ec;
        //socket.shutdown(tcp::socket::shutdown_both, ec);
        stream.close();
        cache->delete_invalid_http_connect(conn_ptr);
    }
    else
    {
        cache->release_http_connect(conn_ptr);
    }
    return std::move(res);
}

StrResponse MultiClientHttp::h1_req(const StrRequest &req, const HttpsReqArgument &args) noexcept
{
    StrResponse res;
    HttpsConnectionPtr conn_ptr = cache->get_https_connect(args);
    if (!conn_ptr)
    {
        res.result(http::status::network_connect_timeout_error);
        return std::move(res);
    }
    ssl::stream<tcp_stream> &stream = conn_ptr->stream;
    BSError ec;
    stream.next_layer().expires_after(std::chrono::seconds(args.req_timeout));
    //发送请求
    http::async_write(stream, req, boost::fibers::asio::yield[ec]);
    if (ec)
    {
        LogErrorExt << ec.message();
        if (ec == boost::beast::error::timeout)
        {
            res.result(http::status::request_timeout);
        }
        else
        {
            res.result(http::status::connection_closed_without_response);
        }
        cache->delete_invalid_https_connect(conn_ptr);
        return std::move(res);
    }
    //返回响应
    boost::beast::flat_buffer b;
    http::async_read(stream, b, res, boost::fibers::asio::yield[ec]);
    if (ec)
    {
        LogErrorExt << ec.message();
        if (ec == boost::beast::error::timeout)
        {
            res.result(http::status::request_timeout);
        }
        else
        {
            res.result(http::status::connection_closed_without_response);
        }
        cache->delete_invalid_https_connect(conn_ptr);
        return std::move(res);
    }
    if (res.need_eof())
    {
        stream.async_shutdown(boost::fibers::asio::yield[ec]);
        if (ec == boost::asio::error::eof)
        {
            // Rationale:
            // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
            ec.assign(0, ec.category());
        }
        cache->delete_invalid_https_connect(conn_ptr);
    }
    else
    {
        cache->release_https_connect(conn_ptr);
    }
    return std::move(res);
}

#ifdef USE_CLIENT_HTTP2
StrResponse MultiClientHttp::h2_req(const StrRequest &req, const HttpsReqArgument& args) noexcept
{
    StrResponse res;
    Http2ConnectionPtr conn_ptr = cache->get_http2s_connect(args);
    if (!conn_ptr)
    {
        res.result(http::status::network_connect_timeout_error);
        return std::move(res);
    }

    //构建http头
    nghttp2::asio_http2::header_map h2_headers;
    for(auto it = req.begin(); it!=req.end(); ++it)
    {
        //Authorization字段值,要区分大小写,加密时需要
        if(it->name_string() == "Authorization")
        {
            h2_headers.emplace(it->name_string().to_string(), nghttp2::asio_http2::header_value{it->value().to_string(), true});
        }
        else
        {
            h2_headers.emplace(it->name_string().to_string(), nghttp2::asio_http2::header_value{it->value().to_string(), false});
        }
    }
    const string& body = req.body();

    Http2Connection& conn = *conn_ptr;
    auto& session = conn.session;

    boost::system::error_code ec;
    const nghttp2::asio_http2::client::request *request = session.submit(ec,
                                                                         req.method_string().to_string(),
                                                                         "https://" + conn.host + ":" + conn.port + req.target().to_string(),
                                                                         body,
                                                                         h2_headers);
    if(ec)
    {
        LogErrorExt << ec.message();
        res.result(http::status::connection_closed_without_response);
        cache->delete_invalid_http2s_connect(conn_ptr);
        return std::move(res);
    }

    std::shared_ptr<boost::fibers::promise<void>> promise(new boost::fibers::promise<void>());
    boost::fibers::future<void> future(promise->get_future());
    string tmp_body;
    request->on_response([&res, &tmp_body, promise](const nghttp2::asio_http2::client::response &response) mutable {
        res.result(static_cast<unsigned>(response.status_code()));
        for (auto &kv : response.header())
        {
            res.insert(kv.first, kv.second.value);
        }
        response.on_data([&tmp_body, promise](const uint8_t *data, std::size_t len ) mutable {
            if(len > 0)
            {
                tmp_body.append(reinterpret_cast<const char*>(data), len);
            }
            else
            {
                promise->set_value();
            }

        });
    });

    boost::fibers::future_status status = future.wait_for(std::chrono::seconds(conn.req_timeout));
    if (status == boost::fibers::future_status::timeout)
    {
        cache->delete_invalid_http2s_connect(conn_ptr);
        res.result(http::status::request_timeout);
        return std::move(res);
    }
    future.get();
    if(!tmp_body.empty())
    {
        res.body() = tmp_body;
        res.prepare_payload();
    }

    return std::move(res);
}
#endif
