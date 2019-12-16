#ifndef EXCEPTION_TRACE_H
#define EXCEPTION_TRACE_H

#define BOOST_STACKTRACE_USE_BACKTRACE
#include <boost/stacktrace.hpp>
#include <boost/exception/all.hpp>

typedef boost::error_info<struct tag_stacktrace, boost::stacktrace::stacktrace> traced;
typedef boost::error_info<struct tag_global_error_code, int> global_error_code;

template <class E>
void throw_with_trace_code(const E &e, int error_code)
{
    throw boost::enable_error_info(e)
            << traced(boost::stacktrace::stacktrace(0, 5)) << global_error_code(error_code);
}

template <class E>
void throw_with_trace(const E &e)
{
    throw boost::enable_error_info(e)
            << traced(boost::stacktrace::stacktrace(0, 5));
}

template <class E>
auto make_with_trace(const E &e)
{
    return std::make_exception_ptr(boost::enable_error_info(e)
                                   << traced(boost::stacktrace::stacktrace(0, 5)));
}

template <class E>
auto make_with_trace_code(const E &e, int error_code)
{
    return std::make_exception_ptr(boost::enable_error_info(e)
                                   << traced(boost::stacktrace::stacktrace(0, 5)) << global_error_code(error_code));
}

#endif
