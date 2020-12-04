#include <iostream>
#include <string>

#include <nghttp2/asio_http2_server.h>

#include <boost/json.hpp>
namespace json = boost::json;
using std::cout;
using std::endl;
using std::string;

int main() {
    try
    {
        boost::system::error_code ec;

        std::string addr = "0.0.0.0";
        std::string port = "28443";
        std::size_t num_threads = 3;
        string key_file = "./server.key";
        string cer_file = "./server.crt";

        nghttp2::asio_http2::server::http2 server;
        server.num_threads(num_threads);
        server.handle("/test_api", [](const nghttp2::asio_http2::server::request &req, const nghttp2::asio_http2::server::response &res) {
            const nghttp2::asio_http2::uri_ref& uri = req.uri();
            cout << req.method() << " " << uri.scheme << " " << uri.host << " " << uri.path << " " << uri.fragment << endl;
            string tmp_body;
            req.on_data([tmp_body = std::move(tmp_body)](const uint8_t * data, std::size_t len) mutable {
                if(len > 0)
                {
                    tmp_body.append(reinterpret_cast<const char*>(data), len);
                }
                else if(!tmp_body.empty())
                {
                    cout << tmp_body << endl;
                }
            });

            res.write_head(200,
                          {
                             {"filed1", {"value1"}},
                             {"field2", {"value2"}}
                          }
                          );
            json::object body;
            body["error_code"] = 0;
            res.end(json::serialize(body));
        });

        boost::asio::ssl::context tls(boost::asio::ssl::context::sslv23);
        SSL_CTX_set_security_level(tls.native_handle(), 1); //不这样设置在新版本openssl库中会报key太短,新版本中默认安全等级为2
        tls.set_options(boost::asio::ssl::context::default_workarounds);
        tls.use_certificate_file(cer_file, boost::asio::ssl::context::pem, ec);
        if(ec)
        {
            cout << "use_certificate_file: " << ec.message() << endl;
            return 1;
        }
        tls.use_private_key_file(key_file, boost::asio::ssl::context::pem, ec);
        if(ec)
        {
            cout << "use_private_key_file: "<< ec.message() << endl;
            return 1;
        }

        nghttp2::asio_http2::server::configure_tls_context_easy(ec, tls);

        if (server.listen_and_serve(ec, tls, addr, port))
        {
            cout << "listen_and_serve: " << ec.message() << std::endl;
        }
    }
    catch (std::exception &e)
    {
        std::cerr << "exception: " << e.what() << "\n";
    }

    return 0;
}
