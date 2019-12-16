#include "logger.h"

#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/common.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/attributes.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/sources/logger.hpp>
#include <boost/core/null_deleter.hpp>

#include <boost/log/sinks/text_ostream_backend.hpp>
#include <boost/log/sinks/syslog_backend.hpp>
#include <boost/log/sinks/text_file_backend.hpp>

#include <boost/log/sinks/async_frontend.hpp>

#include <boost/log/sinks/sync_frontend.hpp>
#include <boost/make_shared.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/fiber/all.hpp>
#include <boost/asio.hpp>

#include <unistd.h>
#include <sys/syscall.h>

using namespace std;

namespace boost {
BOOST_LOG_OPEN_NAMESPACE
namespace sinks {
    class syslog_udp5424_backend :
            public basic_formatted_sink_backend< char >
    {
        //! Base type
        typedef basic_formatted_sink_backend< char > base_type;
        typedef boost::log::aux::light_function< syslog::level (record_view const&) > severity_mapper_type;
    public:
        /*!
         * Constructor. Creates a UDP socket-based backend with <tt>syslog::user</tt> facility code.
         * IPv4 protocol will be used.
         */
        BOOST_LOG_API syslog_udp5424_backend() : m_socket(m_service)
        {

        }
        /*!
         * Destructor
         */
        BOOST_LOG_API ~syslog_udp5424_backend()
        {

        }

        BOOST_LOG_API void set_severity_mapper(severity_mapper_type const& mapper)
        {
            m_level_mapper = mapper;
        }

        BOOST_LOG_API void set_target_address(std::string const& addr, unsigned short port = 514)
        {
            m_process_name = boost::log::aux::get_process_name();
            if(m_process_name.empty())
            {
                m_process_name = "-";
            }
            m_process_id = boost::lexical_cast<string>(boost::log::aux::this_process::get_id().native_id());

            boost::system::error_code ec;
            m_local_hostname = asio::ip::host_name(ec);
            if(m_local_hostname.empty())
            {
                m_local_hostname = "-";
            }
            boost::asio::ip::address vaddr = boost::asio::ip::address::from_string(addr);
            m_target_host = asio::ip::udp::endpoint(vaddr, port);
            if(vaddr.is_v4())
            {
                m_socket.open(boost::asio::ip::udp::v4());
            }
            else
            {
                m_socket.open(boost::asio::ip::udp::v6());
            }
        }

        BOOST_LOG_API void consume(record_view const& rec, string_type const& formatted_message)
        {
            send(m_level_mapper.empty() ? syslog::info : m_level_mapper(rec),
                 formatted_message);
        }

    private:
        void send(syslog::level lev, string_type const& formatted_message)
        {
            int pri = m_facility | static_cast<int>(lev);
            std::time_t t = std::time(nullptr);
            std::tm ts;
            std::tm* time_stamp = boost::date_time::c_time::localtime(&t, &ts);

            // The packet size is mandated in RFC5424, plus one for the terminating zero

            //# 一条信息的构成
            //SYSLOG-MSG = HEADER SP STRUCTURED-DATA [SP MSG]  # 最后的MSG是可省略的
            //# HEADER = 优先级 版本 空格 时间戳 空格 主机名 空格 应用名 空格 进程id 空格 信息id
            //HEADER = PRI VERSION SP TIMESTAMP SP HOSTNAME
            //SP APP-NAME SP PROCID SP MSGID
            //# PRI优先级
            //PRI = "<" PRIVAL ">" # 优先级 <0>
            //# PRI优先级的值
            //PRIVAL = 1*3DIGIT ; range 0 .. 191 # 3位数字, 0到191
            //# syslog版本号
            //VERSION = NONZERO-DIGIT 0*2DIGIT # 默认为 RFC5424默认为1
            //# 主机名
            //HOSTNAME = NILVALUE / 1*255PRINTUSASCII # - 或 255位可打印ASCII值
            //# 应用名
            //APP-NAME = NILVALUE / 1*48PRINTUSASCII # - 或 48位可打印ASCII值
            //# 进程ID
            //PROCID = NILVALUE / 1*128PRINTUSASCII # - 或 128位可打印ASCII值
            //# 信息ID
            //MSGID = NILVALUE / 1*32PRINTUSASCII # - 或 32位可打印ASCII值
            //# 时间戳
            //TIMESTAMP = NILVALUE / FULL-DATE "T" FULL-TIME # - 或 "0000-00-00"
            //# 完整日期格式
            //FULL-DATE = DATE-FULLYEAR "-" DATE-MONTH "-" DATE-MDAY # "0000-00-00"
            //# 年
            //DATE-FULLYEAR = 4DIGIT # 四位数字
            //# 月
            //DATE-MONTH = 2DIGIT ; 01-12 # 两位数字
            //# 日
            //DATE-MDAY = 2DIGIT ; 01-28, 01-29, 01-30, 01-31 based on month/year
            //# 完整时间（带时区）
            //FULL-TIME = PARTIAL-TIME TIME-OFFSET
            //# 时间（不带时区）
            //PARTIAL-TIME = TIME-HOUR ":" TIME-MINUTE ":" TIME-SECOND # 23:59:59
            //[TIME-SECFRAC]
            //# 小时
            //TIME-HOUR = 2DIGIT ; 00-23 # 两位数字
            //# 分
            //TIME-MINUTE = 2DIGIT ; 00-59 # 两位数字
            //# 秒
            //TIME-SECOND = 2DIGIT ; 00-59 # 两位数字
            //# 时间的小数部分
            //TIME-SECFRAC = "." 1*6DIGIT # 6位数字
            //TIME-OFFSET = "Z" / TIME-NUMOFFSET # 相对于标准时区的偏移， "Z" 或 +/- 23:59
            //# 相对于便准时区的偏移
            //TIME-NUMOFFSET = ("+" / "-") TIME-HOUR ":" TIME-MINUTE # +/- 23:59
            //# 结构化数据
            //STRUCTURED-DATA = NILVALUE / 1*SD-ELEMENT # - 或 SD-ELEMENT
            //SD-ELEMENT = "[" SD-ID *(SP SD-PARAM) "]" # [SD-ID*( PARAM-NAME="PARAM-VALUE")]
            //SD-PARAM = PARAM-NAME "=" %d34 PARAM-VALUE %d34 # PARAM-NAME="PARAM-VALUE"
            //SD-ID = SD-NAME # SD-ID
            //PARAM-NAME = SD-NAME # 参数名
            //PARAM-VALUE = UTF-8-STRING # utf-8字符， '"', '\' 和 ']'必须被转义
            //SD-NAME = 1*32PRINTUSASCII # 1到32位可打印ascii值，除了'=',空格, ']', 双引号(")
            //MSG = MSG-ANY / MSG-UTF8 # 信息
            //MSG-ANY = *OCTET ; not starting with BOM # 八进制字符串 不以BOM开头
            //MSG-UTF8 = BOM UTF-8-STRING # utf-8格式字符串
            //BOM = %xEF.BB.BF # 表明编码方式，以 EF BB BF开头表明utf-8编码
            //UTF-8-STRING = *OCTET # RFC 3629规定的字符
            //OCTET = %d00-255 # ascii
            //SP = %d32 # 空格
            //PRINTUSASCII = %d33-126 # ascii值的33-126，即数字、大小写字母、标点符号
            //NONZERO-DIGIT = %d49-57 # ascii的49-57
            //DIGIT = %d48 / NONZERO-DIGIT # ascii的48-57
            //NILVALUE = "-" # 无对应值
            char packet[2048];
            int n = boost::log::aux::snprintf
                    (
                        packet,
                        sizeof(packet),
                        "<%d>1 %4d-%02d-%02dT%02d:%02d:%02d %s %s %s %s - %s",
                        pri,
                        time_stamp->tm_year + 1900,
                        time_stamp->tm_mon + 1,
                        time_stamp->tm_mday,
                        time_stamp->tm_hour,
                        time_stamp->tm_min,
                        time_stamp->tm_sec,
                        m_local_hostname.c_str(),
                        m_process_name.c_str(),
                        m_process_id.c_str(),
                        m_msg_id.c_str(),
                        formatted_message.c_str()
                        );
            if (n > 0)
            {
                std::size_t packet_size = static_cast<std::size_t>(n) >= sizeof(packet) ? sizeof(packet) - 1u : static_cast< std::size_t >(n);
                m_socket.send_to(asio::buffer(packet, packet_size), m_target_host);
            }
        }

    private:
        boost::asio::io_service m_service;
        boost::asio::ip::udp::socket m_socket;
        severity_mapper_type m_level_mapper;
        asio::ip::udp::endpoint m_target_host;
        std::string m_local_hostname;
        std::string m_process_name;
        std::string m_process_id;
        std::string m_msg_id = "-";
        int m_facility = syslog::user;

    };
}
BOOST_LOG_CLOSE_NAMESPACE
}


namespace logging = boost::log;
namespace attrs = boost::log::attributes;
namespace src = boost::log::sources;
namespace sinks = boost::log::sinks;
namespace expr = boost::log::expressions;
namespace keywords = boost::log::keywords;

#ifdef KLOGGER_ASYNC
typedef sinks::asynchronous_sink< sinks::text_ostream_backend > StreamSink;
typedef sinks::asynchronous_sink< sinks::text_file_backend > FileSink;
typedef sinks::asynchronous_sink< sinks::syslog_udp5424_backend > SyslogSink;
#else
typedef sinks::synchronous_sink<sinks::text_ostream_backend> StreamSink;
typedef sinks::synchronous_sink<sinks::text_file_backend> FileSink;
typedef sinks::synchronous_sink<sinks::syslog_udp5424_backend> SyslogSink;
#endif

namespace {
    inline long get_thread_pid()
    {
        return syscall(SYS_gettid);
    }

} //namespace

//logName示例: /var/log/test.log
void init_logging(const std::string &log_path, logging::trivial::severity_level filter_level)
{
    logging::add_common_attributes();
    logging::core::get()->add_global_attribute(
           "ThreadPID",
           attrs::make_function(&get_thread_pid));
    logging::core::get()->add_global_attribute(
                "FiberID",
                attrs::make_function(&boost::this_fiber::get_id));

    boost::filesystem::path path_log_filename(log_path);
    boost::filesystem::path parent_path = path_log_filename.parent_path();
    boost::filesystem::path stem = path_log_filename.stem();
    boost::filesystem::path extension_name = path_log_filename.extension();
    auto core = logging::core::get();

    //这里不使用target_file_name,因为程序重启以前的file_name内容会被清空,这里不想使用日志追加
    boost::shared_ptr<sinks::text_file_backend> file_backend = boost::make_shared<sinks::text_file_backend>(
                keywords::file_name = parent_path.string() + "/" + stem.string() + "_%6N" + extension_name.string(),
                //keywords::target_file_name = parent_path.string() + "/" + stem.string() + "_%6N" + extension_name.string(),
                keywords::rotation_size = 50 * 1024 * 1024
            //keywords::time_based_rotation = sinks::file::rotation_at_time_point(0,0,0)
            );
#ifndef KLOGGER_FORBIDDEN_AUTO_FLUSH
    //写入日志文件的默认使用 auto_flush，防止日志丢失, false会缓冲
    file_backend->auto_flush(true);
#else
    file_backend->auto_flush(true);
#endif

    boost::shared_ptr<FileSink> file_sink = boost::make_shared<FileSink>(file_backend);
    file_sink->locked_backend()->set_file_collector(
                sinks::file::make_collector(
                    keywords::target = parent_path.string(),
                    keywords::max_size = (uintmax_t)5 * 1024 * 1024 * 1024,
                    keywords::min_free_space = 100 * 1024 * 1024));
    core->add_sink(file_sink);

    file_sink->set_filter(expr::attr<logging::trivial::severity_level>("Severity") >= filter_level);
    file_sink->set_formatter(
                expr::stream
                << "[" << expr::format_date_time<boost::posix_time::ptime>("TimeStamp", "%Y-%m-%d %H:%M:%S.%f") << "]"
                << "[" << expr::attr<logging::trivial::severity_level>("Severity") << "]"
                << "[" << expr::attr<long>("ThreadPID") << "]"
                << "[" << expr::attr<boost::fibers::fiber::id>("FiberID") << "]"
                << " " << expr::max_size_decor(1024*50, ">>>")[expr::stream << expr::message]
                );
    file_sink->locked_backend()->scan_for_files();

    //输出控制台
    auto console_backend = boost::make_shared<sinks::text_ostream_backend>();
    console_backend->add_stream(
                boost::shared_ptr<std::ostream>(&std::clog, boost::null_deleter()));

#ifndef KLOGGER_FORBIDDEN_AUTO_FLUSH
    //指定立刻将日志打印到屏幕, false会缓冲日志，直到合适的时候再打印到屏幕，防止日志量太大时 io 压力过大
    console_backend->auto_flush(true);
#else
    console_backend->auto_flush(false);
#endif

    boost::shared_ptr<StreamSink> console_sink = boost::make_shared<StreamSink>(console_backend);
    core->add_sink(console_sink);

    console_sink->set_filter(expr::attr<logging::trivial::severity_level>("Severity") >= filter_level);
    console_sink->set_formatter(
                expr::stream
                << "[" << expr::format_date_time<boost::posix_time::ptime>("TimeStamp", "%Y-%m-%d %H:%M:%S.%f") << "]"
                << "[" << expr::attr<logging::trivial::severity_level>("Severity") << "]"
                << "[" << expr::attr<long>("ThreadPID") << "]"
                << "[" << expr::attr<boost::fibers::fiber::id>("FiberID") << "]"
                << " " << expr::max_size_decor(1024*50, ">>>")[expr::stream << expr::message]
                );
}

void add_syslogging(const std::string& syslog_server_ip, int syslog_server_port, boost::log::trivial::severity_level filter_level)
{
    boost::shared_ptr<sinks::syslog_udp5424_backend> backend(new sinks::syslog_udp5424_backend());
    backend->set_target_address(syslog_server_ip, syslog_server_port);
    sinks::syslog::custom_severity_mapping<logging::trivial::severity_level> mapping("Severity");
    mapping[logging::trivial::debug] = sinks::syslog::debug;
    mapping[logging::trivial::info] = sinks::syslog::info;
    mapping[logging::trivial::warning] = sinks::syslog::warning;
    mapping[logging::trivial::error] = sinks::syslog::error;
    mapping[logging::trivial::fatal] = sinks::syslog::critical;
    backend->set_severity_mapper(mapping);

    auto core = logging::core::get();
    boost::shared_ptr<SyslogSink> syslog_sink = boost::make_shared<SyslogSink>(backend);
    core->add_sink(syslog_sink);

    syslog_sink->set_filter(expr::attr<logging::trivial::severity_level>("Severity") >= filter_level);
    syslog_sink->set_formatter(
                expr::stream
                << "[" << expr::format_date_time<boost::posix_time::ptime>("TimeStamp", "%Y-%m-%d %H:%M:%S.%f") << "]"
                << "[" << expr::attr<logging::trivial::severity_level>("Severity") << "]"
                << "[" << expr::attr<long>("ThreadPID") << "]"
                << "[" << expr::attr<boost::fibers::fiber::id>("FiberID") << "]"
                << " " << expr::smessage);
}
