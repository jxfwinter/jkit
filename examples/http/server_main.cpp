#include "fiber_frame_context.hpp"

#include <boost/json.hpp>
#include "http_api_server.h"

namespace json = boost::json;
class TestApi : public HttpApiServer
{
public:
    TestApi(const string& listen_address, uint16_t listen_port) :
        HttpApiServer(3, listen_address, listen_port)
    {
        m_resource["^/test_api$"][http::verb::get] = [this](HttpContext& cxt) {
            json::object res;
            res["error_code"] = 0;
            cxt.res.body() = json::serialize(res);
        };
    }
};

int main()
{
    FiberFrameContext& frame_cxt = FiberFrameContext::instance();
    frame_cxt.run_thread_count = 2;
    frame_cxt.init();

    init_logging("./restful_server.log", boost::log::trivial::debug);

    TestApi api("0.0.0.0", 28080);
    api.start();

    //模拟停止
    /*
     * boost::fibers::fiber([&api, &frame_cxt](){
        boost::this_fiber::sleep_for(std::chrono::seconds(5));
        api.stop();
        std::cout << "api stop()\n";
        boost::this_fiber::sleep_for(std::chrono::seconds(5));
        api.start();
        std::cout << "api start()\n";
    }).detach();
    */

    frame_cxt.wait();
    return 0;
}
