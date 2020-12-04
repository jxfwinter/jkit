#include "multi_client_http.h"
#include "logger.h"
#include <iostream>
#include <sstream>
#include <string>
#include <mutex>
#include <atomic>
#include <boost/json.hpp>
using std::cout;
using std::endl;
namespace json = boost::json;

string g_host = "127.0.0.1";
string g_port = "28080";
string g_target = "/test_api";
int g_request_count = 300;
int g_response_count;
boost::fibers::condition_variable_any g_cnd;
boost::fibers::mutex g_mux;
typedef std::unique_lock<boost::fibers::mutex> fflock;


void do_session()
{
    try
    {
        HttpReqArgument args;
        args.host = g_host;
        args.port = g_port;
        StrRequest req{http::verb::get, g_target, 11};
        req.set(http::field::host, g_host);
        //req.keep_alive(false);

        StrResponse res = MultiClientHttp::h1_req(req, args);
        cout << res << "\n" << g_response_count << endl;

        fflock lk(g_mux);
        ++g_response_count;
        if(g_response_count == g_request_count)
        {
            g_cnd.notify_all();
        }
    }
    catch(std::exception& e)
    {
        std::cerr << e.what() << std::endl;
    }
}

int main(int argc, char** argv)
{
    if(argc != 5)
    {
        std::cerr <<
                     "Usage: " << argv[0] << " <host> <port> <target> <count>\n" <<
                     "Example:\n    " << argv[0] <<
                     " 127.0.0.1 28080 /test_api 300 \n";
        return EXIT_FAILURE;
    }

    g_host = argv[1];
    g_port = argv[2];
    g_target = argv[3];
    g_request_count = static_cast<int>(std::atoi(argv[4]));

    init_logging("./test_client.log", boost::log::trivial::debug);

    boost::fibers::use_scheduling_algorithm<boost::fibers::algo::round_robin>();
    MultiClientHttp::init();

    while(1)
    {
        g_response_count = 0;
        for(int i=0; i<g_request_count; ++i)
        {
            boost::fibers::fiber(&do_session).detach();
        }

        {
            fflock lk(g_mux);
            g_cnd.wait(lk, [](){
                return g_response_count == g_request_count;
            });
        }

        boost::this_fiber::sleep_for(std::chrono::seconds(5));
    }
    return EXIT_SUCCESS;
}
