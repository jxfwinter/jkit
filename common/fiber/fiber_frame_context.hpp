#ifndef FIBER_FRAME_CONTEXT_HPP
#define FIBER_FRAME_CONTEXT_HPP

#include <vector>
#include <thread>
#include <mutex>
#include <boost/fiber/all.hpp>

//只能有一个实例,并且要在main入口处理调用 init() 在main返回前调用 wait()
//如果想要停止并退出进程,需要调用 notify_stop()
class FiberFrameContext
{
public:
    int run_thread_count = 2; //开启的线程数量
    static FiberFrameContext& instance();

    void init();

    void notify_stop();

    void wait();

private:
    FiberFrameContext() = default;
    FiberFrameContext(const FiberFrameContext& rhs) = delete;
    FiberFrameContext(FiberFrameContext&& rhs) = delete;

    FiberFrameContext& operator = (const FiberFrameContext& rhs) = delete;
    FiberFrameContext& operator = (FiberFrameContext&& rhs) = delete;

    static FiberFrameContext m_cxt;

    bool m_running = true;
    std::mutex m_mtx;
    boost::fibers::condition_variable_any m_cnd_stop;
    std::vector<std::thread> m_threads;
};

FiberFrameContext& FiberFrameContext::instance()
{
    return m_cxt;
}

FiberFrameContext FiberFrameContext::m_cxt;

void FiberFrameContext::init()
{
    auto thread_fun = [this](){
        boost::fibers::use_scheduling_algorithm<boost::fibers::algo::work_stealing>(run_thread_count, true);
        //检查结束条件
        {
            std::unique_lock<std::mutex> lk(m_mtx);
            m_cnd_stop.wait(lk, [this]() { return !m_running; } );
        }
    };

    for(int i=1; i<run_thread_count; ++i)
    {
        m_threads.push_back(std::thread(thread_fun));
    }
    boost::fibers::use_scheduling_algorithm<boost::fibers::algo::work_stealing>(run_thread_count, true);
}

void FiberFrameContext::notify_stop()
{
    std::unique_lock<std::mutex> lk(m_mtx);
    m_running = false;
    lk.unlock();
    m_cnd_stop.notify_all();
}

void FiberFrameContext::wait()
{
    //检查结束条件
    {
        std::unique_lock<std::mutex> lk(m_mtx);
        m_cnd_stop.wait(lk, [this]() { return !m_running; } );
    }

    for (std::thread & t : m_threads)
    {
        t.join();
    }
}

#endif // FIBER_FRAME_CONTEXT_HPP
