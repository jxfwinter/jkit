#include "test_api.hpp"
#include "fiber_frame_context.hpp"

int main()
{
    FiberFrameContext& frame_cxt = FiberFrameContext::instance();
    frame_cxt.run_thread_count = 3;
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
