#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <fstream>
#include <list>
#include <locale>
#include <string>
#include <ctime>
#include <boost/log/trivial.hpp>
#include <boost/format.hpp>

/*
宏定义说明
KLOGGER_FORBIDDEN_AUTO_FLUSH 表示每行日志立即刷新到文件或终端
KLOGGER_ASYNC  表示启用异步日志
*/

#define LogTrace	BOOST_LOG_TRIVIAL(trace)
#define LogDebug	BOOST_LOG_TRIVIAL(debug)
#define LogInfo		BOOST_LOG_TRIVIAL(info)
#define LogWarn		BOOST_LOG_TRIVIAL(warning)
#define LogError	BOOST_LOG_TRIVIAL(error)
#define LogFatal	BOOST_LOG_TRIVIAL(fatal)

#define LogDebugExt	LogDebug << __FILE__ << ",line " << __LINE__ << ","
#define LogErrorExt LogError << __FILE__ << ",line " << __LINE__ << ","
#define LogWarnExt LogWarn << __FILE__ << ",line " << __LINE__ << ","
#define LogFatalExt LogFatal << __FILE__ << ",line " << __LINE__ << ","


template<typename... Arguments>
void log_trace(const std::string& fmt, Arguments&&... args)
{
   BOOST_LOG_TRIVIAL(trace) << (boost::format(fmt) % ... %std::forward<Arguments>(args));
}

template<typename... Arguments>
void log_debug(const std::string& fmt, Arguments&&... args)
{
   BOOST_LOG_TRIVIAL(debug) << (boost::format(fmt) % ... %std::forward<Arguments>(args));
}

template<typename... Arguments>
void log_info(const std::string& fmt, Arguments&&... args)
{
   BOOST_LOG_TRIVIAL(info) << (boost::format(fmt) % ... %std::forward<Arguments>(args));
}

template<typename... Arguments>
void log_warning(const std::string& fmt, Arguments&&... args)
{
   BOOST_LOG_TRIVIAL(warning) << (boost::format(fmt) % ... %std::forward<Arguments>(args));
}

template<typename... Arguments>
void log_warning_prefix(const char* file, int line, const std::string& fmt, Arguments&&... args)
{
   BOOST_LOG_TRIVIAL(warning) << file << ",line " << line << "," << (boost::format(fmt) % ... %std::forward<Arguments>(args));
}
#define log_warning_ext(fmt, ...) log_warning_prefix(__FILE__, __LINE__, fmt __VA_OPT__(,) __VA_ARGS__)

template<typename... Arguments>
void log_error(const std::string& fmt, Arguments&&... args)
{
   BOOST_LOG_TRIVIAL(error) << (boost::format(fmt) % ... %std::forward<Arguments>(args));
}

template<typename... Arguments>
void log_error_with_prefix(const char* file, int line, const std::string& fmt, Arguments&&... args)
{
   BOOST_LOG_TRIVIAL(error) << file << ",line " << line << "," << (boost::format(fmt) % ... %std::forward<Arguments>(args));
}

#define log_error_ext(fmt, ...) log_error_with_prefix(__FILE__, __LINE__, fmt __VA_OPT__(,) __VA_ARGS__)

template<typename... Arguments>
void log_fatal(const std::string& fmt, Arguments&&... args)
{
   BOOST_LOG_TRIVIAL(fatal) << (boost::format(fmt) % ... %std::forward<Arguments>(args));
}

template<typename... Arguments>
void log_fatal_prefix(const char* file, int line, const std::string& fmt, Arguments&&... args)
{
   BOOST_LOG_TRIVIAL(fatal) << file << ",line " << line << "," << (boost::format(fmt) % ... %std::forward<Arguments>(args));
}

#define log_fatal_ext(fmt, ...) log_fatal_prefix(__FILE__, __LINE__, fmt __VA_OPT__(,) __VA_ARGS__)


//注意,异步日志在压力测试时,会因为日志队列导致内存不断增长

//必须先调用
void init_logging(const std::string &log_path, boost::log::trivial::severity_level filter_level);

void add_syslogging(const std::string& syslog_server_ip, int syslog_server_port, boost::log::trivial::severity_level filter_level);

#endif
