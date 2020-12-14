#include "http_api_server.h"

namespace
{
// 设置心跳
void set_socket_opt(socket_type s)
{
    int flags = 1;
    int tcp_keepalive_time = 20;
    int tcp_keepalive_probes = 3;
    int tcp_keepalive_intvl = 3;
    int ret = 0;
    ret = setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &flags, sizeof(flags));
    if (ret < 0)
    {
        LogErrorExt << "setsockopt SO_KEEPALIVE failed";
    }
    ret = setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE, &tcp_keepalive_time, sizeof(tcp_keepalive_time));
    if (ret < 0)
    {
        LogErrorExt << "setsockopt TCP_KEEPIDLE failed";
    }
    ret = setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, &tcp_keepalive_intvl, sizeof(tcp_keepalive_intvl));
    if (ret < 0)
    {
        LogErrorExt << "setsockopt TCP_KEEPINTVL failed";
    }
    ret = setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT, &tcp_keepalive_probes, sizeof(tcp_keepalive_probes));
    if (ret < 0)
    {
        LogErrorExt << "setsockopt TCP_KEEPCNT failed";
    }
}

//启用close-on-exec机制
void set_close_on_exec(socket_type s)
{
    int flags = fcntl(s, F_GETFD);
    flags |= FD_CLOEXEC;
    fcntl(s, F_SETFD, flags);
}
} // namespace

HttpApiServer::HttpApiServer(int thread_count, const string& listen_address, uint16_t listen_port) :
    m_thread_count(thread_count), m_work(new IoContextWork(m_io_cxt.get_executor())), m_acceptor(m_io_cxt)
{
    m_listen_ep = Endpoint{boost::asio::ip::address::from_string(listen_address), listen_port};
    m_default_resource = [](HttpContext &cxt) {
        cxt.res.result(http::status::not_found);
        cxt.res.version(cxt.req.version());
        cxt.res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        cxt.res.set(http::field::content_type, "text/html");
        cxt.res.keep_alive(false);
        cxt.res.body() = "The '" + cxt.req.method_string().to_string() + "' resource '" + cxt.path + "' was not found.";
        cxt.res.prepare_payload();
    };

    m_bad_resource = [](HttpContext &cxt, const string &why) {
        cxt.res.result(http::status::bad_request);
        cxt.res.version(cxt.req.version());
        cxt.res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        cxt.res.set(http::field::content_type, "text/html");
        cxt.res.keep_alive(false);
        cxt.res.body() = why;
        cxt.res.prepare_payload();
    };
}

HttpApiServer::~HttpApiServer()
{
}

void HttpApiServer::session(tcp_stream &stream)
{
    set_socket_opt(stream.socket().native_handle());
    bool close = false;
    boost::system::error_code ec;

    // This buffer is required to persist across reads
    boost::beast::flat_buffer buffer;
    HttpContext cxt;
    cxt.remote_endpoint = stream.socket().remote_endpoint(ec);
    if (ec)
    {
        LogErrorExt << ec.message();
        return;
    }

    while (m_running)
    {
        if (0 != m_timeout)
        {
            stream.expires_after(std::chrono::seconds(m_timeout));
        }

        // Read a request
        http::request_parser<http::string_body> parser;
        if (m_body_limit > 0)
        {
            parser.body_limit(m_body_limit);
        }

        http::async_read_header(stream, buffer, parser, boost::fibers::asio::yield[ec]);
        if (ec == http::error::end_of_stream)
        {
            break;
        }
        if (ec)
        {
            LogErrorExt << ec.message();
            return;
        }
        if (parser.get()[http::field::expect] == "100-continue")
        {
            // send 100 response
            http::response<http::empty_body> continue_res;
            continue_res.version(11);
            continue_res.result(http::status::continue_);
            continue_res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            LogDebug << continue_res;
            http::async_write(stream, continue_res, boost::fibers::asio::yield[ec]);
            if (ec)
            {
                LogErrorExt << ec.message();
                return;
            }
        }

        http::async_read(stream, buffer, parser, boost::fibers::asio::yield[ec]);
        if (ec)
        {
            LogErrorExt << ec.message();
            return;
        }
        cxt.req = parser.release();
        LogDebug << "req:" << cxt.req;
        first_process(cxt);
        handle_request(cxt);
        last_process(cxt);
        LogDebug << "res:" << cxt.res;
        close = cxt.res.need_eof();
        http::async_write(stream, cxt.res, boost::fibers::asio::yield[ec]);
        if (ec)
        {
            LogErrorExt << ec.message();
            return;
        }
        if (close)
        {
            break;
        }
    }

    stream.close();
}

void HttpApiServer::accept()
{
    m_acceptor.open(m_listen_ep.protocol());
    m_acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    m_acceptor.bind(m_listen_ep);
    m_acceptor.listen();

    //启用close-on-exec机制
    set_close_on_exec(m_acceptor.native_handle());
    boost::system::error_code ec;
    for (;;)
    {
        TcpSocket socket(m_io_cxt);
        m_acceptor.async_accept(socket, boost::fibers::asio::yield[ec]);
        if (ec)
        {
            if (ec.value() == boost::asio::error::no_descriptors)
            {
                LogErrorExt << ec.message();
                continue;
            }
            else if (ec.value() == boost::asio::error::operation_aborted) //主动关闭结束
            {
                LogWarnExt << ec.message();
                break;
            }
            else
            {
                LogErrorExt << ec.message();
                throw boost::system::system_error(ec);
            }
        }
        else
        {
            boost::fibers::fiber([s = std::move(socket), this]() mutable {
                try
                {
                    tcp_stream ts(std::move(s));
                    this->session(ts);
                }
                catch (std::exception const &e)
                {
                    LogErrorExt << e.what() << "," << typeid(e).name();
                }
                std::lock_guard<boost::fibers::mutex> lk(m_session_mutex);
                --m_session_number;
                if (!m_running && m_session_number == 0)
                {
                    m_session_cnd.notify_one();
                }
            }).detach();

            std::lock_guard<boost::fibers::mutex> lk(m_session_mutex);
            ++m_session_number;
        }
    }
}

void HttpApiServer::start()
{
    m_io_cxt.restart();
    m_running = true;
    {
        std::lock_guard<boost::fibers::mutex> lk(m_session_mutex);
        m_session_number = 0;
    }

    m_accept_fiber = boost::fibers::fiber([this]() {
        this->accept();
    });

    for (int i = 0; i < m_thread_count; ++i)
    {
        std::thread t([this]() {
            m_io_cxt.run();
        });
        m_threads.push_back(std::move(t));
    }
}

void HttpApiServer::stop()
{
    m_running = false;
    boost::system::error_code ec;
    m_acceptor.close(ec);
    if (m_accept_fiber.joinable())
    {
        m_accept_fiber.join();
    }

    {
        std::unique_lock<boost::fibers::mutex> lk(m_session_mutex);
        m_session_cnd.wait(lk, [this]() {
            return m_session_number == 0;
        });
    }

    m_io_cxt.stop();
    for (int i = 0; i < m_thread_count; ++i)
    {
        m_threads[i].join();
    }
}

void HttpApiServer::handle_request(HttpContext &cxt)
{
    cxt.res = {};
    StrRequest &req = cxt.req;

    // Request path must be absolute and not contain "..".
    if (req.target().empty() ||
            req.target()[0] != '/' ||
            req.target().find("..") != boost::beast::string_view::npos)
    {
        m_bad_resource(cxt, "path must be absolute and not contain \"..\"");
        return;
    }

    string query_string;
    if (!kkurl::parse_target(req.target(), cxt.path, query_string))
    {
        m_bad_resource(cxt, "parse target failed");
        return;
    }

    cxt.query_params = kkurl::parse_query_string(query_string);

    try
    {
        if (!call_resource(cxt))
        {
            m_default_resource(cxt);
            return;
        }
    }
    catch (std::exception &e)
    {
        m_bad_resource(cxt, e.what());
        return;
    }

    cxt.res.version(req.version());
    cxt.res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    cxt.res.content_length(cxt.res.body().size());
    cxt.res.keep_alive(req.keep_alive());
}

bool HttpApiServer::call_resource(HttpContext &cxt)
{
    auto method = cxt.req.method();
    for (auto &regex_method : m_resource)
    {
        auto it = regex_method.second.find(method);
        if (it != regex_method.second.end())
        {
            boost::smatch sm_res;
            if (boost::regex_match(cxt.path, sm_res, regex_method.first))
            {
                cxt.path_params = std::move(sm_res);
                auto &fun = it->second;
                fun(cxt);
                return true;
            }
        }
    }

    return false;
}
