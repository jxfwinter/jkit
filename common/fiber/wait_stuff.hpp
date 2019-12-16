#ifndef WAIT_STUFF_HPP
#define WAIT_STUFF_HPP

#include <algorithm>
#include <cassert>
#include <chrono>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <boost/fiber/all.hpp>
#include <boost/noncopyable.hpp>
#include <boost/variant/variant.hpp>
#include <boost/variant/get.hpp>

/*****************************************************************************
*   Done
*****************************************************************************/
//[wait_done
// Wrap canonical pattern for condition_variable + bool flag
struct Done {
private:
    boost::fibers::condition_variable   cond;
    boost::fibers::mutex                mutex;
    bool                                ready = false;

public:
    typedef std::shared_ptr< Done >     ptr;

    void wait() {
        std::unique_lock< boost::fibers::mutex > lock( mutex);
        cond.wait( lock, [this](){ return ready; });
    }

    void notify() {
        {
            std::unique_lock< boost::fibers::mutex > lock( mutex);
            ready = true;
        } // release mutex
        cond.notify_one();
    }
};
//]

/*****************************************************************************
*   when_any, simple completion
*****************************************************************************/
//[wait_first_simple_impl
// Degenerate case: when there are no functions to wait for, return
// immediately.
inline void wait_first_simple_impl( Done::ptr) {
}

// When there's at least one function to wait for, launch it and recur to
// process the rest.
template< typename Fn, typename ... Fns >
void wait_first_simple_impl( Done::ptr done, Fn && function, Fns && ... functions) {
    boost::fibers::fiber( [done, function](){
                              function();
                              done->notify();
                          }).detach();
    wait_first_simple_impl( done, std::forward< Fns >( functions) ... );
}
//]

// interface function: instantiate Done, launch tasks, wait for Done
//[wait_first_simple
template< typename ... Fns >
void wait_first_simple( Fns && ... functions) {
    // Use shared_ptr because each function's fiber will bind it separately,
    // and we're going to return before the last of them completes.
    auto done( std::make_shared< Done >() );
    wait_first_simple_impl( done, std::forward< Fns >( functions) ... );
    done->wait();
}
//]
//[wait_first_simple_c
template< typename Fn >
void wait_first_simple_c( std::vector<Fn> && functions) {
    // Use shared_ptr because each function's fiber will bind it separately,
    // and we're going to return before the last of them completes.
    auto done( std::make_shared< Done >() );
    for(auto&& f : functions) {
        wait_first_simple_impl( done, std::forward<Fn>( f));
    }
    done->wait();
}
//]

/*****************************************************************************
*   when_any, return value
*****************************************************************************/
// When there's only one function, call this overload
//[wait_first_value_impl
template< typename T, typename Fn >
void wait_first_value_impl( std::shared_ptr< boost::fibers::buffered_channel< T > > chan,
                            Fn && function) {
    boost::fibers::fiber( [chan, function](){
                              // Ignore channel_op_status returned by push():
                              // might be closed; we simply don't care.
                              chan->push( function() );
                          }).detach();
}
//]

// When there are two or more functions, call this overload
template< typename T, typename Fn0, typename Fn1, typename ... Fns >
void wait_first_value_impl( std::shared_ptr< boost::fibers::buffered_channel< T > > chan,
                            Fn0 && function0,
                            Fn1 && function1,
                            Fns && ... functions) {
    // process the first function using the single-function overload
    wait_first_value_impl< T >( chan,
                                std::forward< Fn0 >( function0) );
    // then recur to process the rest
    wait_first_value_impl< T >( chan,
                                std::forward< Fn1 >( function1),
                                std::forward< Fns >( functions) ... );
}

//[wait_first_value
// Assume that all passed functions have the same return type. The return type
// of wait_first_value() is the return type of the first passed function. It is
// simply invalid to pass NO functions.
template< typename Fn, typename ... Fns >
typename std::result_of< Fn() >::type
wait_first_value( Fn && function, Fns && ... functions) {
    typedef typename std::result_of< Fn() >::type return_t;
    typedef boost::fibers::buffered_channel< return_t > channel_t;
    auto chanp( std::make_shared< channel_t >( 64) );
    // launch all the relevant fibers
    wait_first_value_impl< return_t >( chanp,
                                       std::forward< Fn >( function),
                                       std::forward< Fns >( functions) ... );
    // retrieve the first value
    return_t value( chanp->value_pop() );
    // close the channel: no subsequent push() has to succeed
    chanp->close();
    return value;
}
//]
//[wait_first_value_c
template< typename Fn >
typename std::result_of< Fn() >::type
wait_first_value_c( std::vector< Fn >&& functions) {
    typedef typename std::result_of< Fn() >::type return_t;
    typedef boost::fibers::buffered_channel< return_t > channel_t;
    auto chanp( std::make_shared< channel_t >( 64) );
    // launch all the relevant fibers
    for( auto&& f : functions ) {
        wait_first_value_impl< return_t >( chanp, std::forward< Fn >( f) );
    }
    // retrieve the first value
    return_t value( chanp->value_pop() );
    // close the channel: no subsequent push() has to succeed
    chanp->close();
    return value;
}
//]


/*****************************************************************************
*   when_any, produce first outcome, whether result or exception
*****************************************************************************/
// When there's only one function, call this overload.
//[wait_first_outcome_impl
template< typename T, typename CHANP, typename Fn >
void wait_first_outcome_impl( CHANP chan, Fn && function) {
    boost::fibers::fiber(
        // Use std::bind() here for C++11 compatibility. C++11 lambda capture
        // can't move a move-only Fn type, but bind() can. Let bind() move the
        // channel pointer and the function into the bound object, passing
        // references into the lambda.
        std::bind(
            []( CHANP & chan,
                typename std::decay< Fn >::type & function) {
                // Instantiate a packaged_task to capture any exception thrown by
                // function.
                boost::fibers::packaged_task< T() > task( function);
                // Immediately run this packaged_task on same fiber. We want
                // function() to have completed BEFORE we push the future.
                task();
                // Pass the corresponding future to consumer. Ignore
                // channel_op_status returned by push(): might be closed; we
                // simply don't care.
                chan->push( task.get_future() );
            },
            chan,
            std::forward< Fn >( function)
        )).detach();
}
//]

// When there are two or more functions, call this overload
template< typename T, typename CHANP, typename Fn0, typename Fn1, typename ... Fns >
void wait_first_outcome_impl( CHANP chan,
                              Fn0 && function0,
                              Fn1 && function1,
                              Fns && ... functions) {
    // process the first function using the single-function overload
    wait_first_outcome_impl< T >( chan,
                                  std::forward< Fn0 >( function0) );
    // then recur to process the rest
    wait_first_outcome_impl< T >( chan,
                                  std::forward< Fn1 >( function1),
                                  std::forward< Fns >( functions) ... );
}

// Assume that all passed functions have the same return type. The return type
// of wait_first_outcome() is the return type of the first passed function. It is
// simply invalid to pass NO functions.
//[wait_first_outcome
template< typename Fn, typename ... Fns >
typename std::result_of< Fn() >::type
wait_first_outcome( Fn && function, Fns && ... functions) {
    // In this case, the value we pass through the channel is actually a
    // future -- which is already ready. future can carry either a value or an
    // exception.
    typedef typename std::result_of< Fn() >::type return_t;
    typedef boost::fibers::future< return_t > future_t;
    typedef boost::fibers::buffered_channel< future_t > channel_t;
    auto chanp(std::make_shared< channel_t >( 64) );
    // launch all the relevant fibers
    wait_first_outcome_impl< return_t >( chanp,
                                         std::forward< Fn >( function),
                                         std::forward< Fns >( functions) ... );
    // retrieve the first future
    future_t future( chanp->value_pop() );
    // close the channel: no subsequent push() has to succeed
    chanp->close();
    // either return value or throw exception
    return future.get();
}
//]
//[wait_first_outcome_c
template< typename Fn >
typename std::result_of< Fn() >::type
wait_first_outcome_c( std::vector< Fn > && functions) {
    // In this case, the value we pass through the channel is actually a
    // future -- which is already ready. future can carry either a value or an
    // exception.
    typedef typename std::result_of< Fn() >::type return_t;
    typedef boost::fibers::future< return_t > future_t;
    typedef boost::fibers::buffered_channel< future_t > channel_t;
    auto chanp(std::make_shared< channel_t >( 64) );
    // launch all the relevant fibers
    for(auto&& f : functions) {
        wait_first_outcome_impl< return_t >( chanp, std::forward< Fn >( f) );
    }
    // retrieve the first future
    future_t future( chanp->value_pop() );
    // close the channel: no subsequent push() has to succeed
    chanp->close();
    // either return value or throw exception
    return future.get();
}
//]


/*****************************************************************************
*   when_any, collect exceptions until success; throw exception_list if no
*   success
*****************************************************************************/
// define an exception to aggregate exception_ptrs; prefer
// std::exception_list (N4407 et al.) once that becomes available
//[exception_list
class exception_list : public std::runtime_error {
public:
    exception_list( std::string const& what) :
        std::runtime_error( what) {
    }

    typedef std::vector< std::exception_ptr >   bundle_t;

    // N4407 proposed std::exception_list API
    typedef bundle_t::const_iterator iterator;

    std::size_t size() const noexcept {
        return bundle_.size();
    }

    iterator begin() const noexcept {
        return bundle_.begin();
    }

    iterator end() const noexcept {
        return bundle_.end();
    }

    // extension to populate
    void add( std::exception_ptr ep) {
        bundle_.push_back( ep);
    }

private:
    bundle_t bundle_;
};
//]

// Assume that all passed functions have the same return type. The return type
// of wait_first_success() is the return type of the first passed function. It is
// simply invalid to pass NO functions.
//[wait_first_success
template< typename Fn, typename ... Fns >
typename std::result_of< Fn() >::type
wait_first_success( Fn && function, Fns && ... functions) {
    std::size_t count( 1 + sizeof ... ( functions) );
    // In this case, the value we pass through the channel is actually a
    // future -- which is already ready. future can carry either a value or an
    // exception.
    typedef typename std::result_of< typename std::decay< Fn >::type() >::type return_t;
    typedef boost::fibers::future< return_t > future_t;
    typedef boost::fibers::buffered_channel< future_t > channel_t;
    auto chanp( std::make_shared< channel_t >( 64) );
    // launch all the relevant fibers
    wait_first_outcome_impl< return_t >( chanp,
                                         std::forward< Fn >( function),
                                         std::forward< Fns >( functions) ... );
    // instantiate exception_list, just in case
    exception_list exceptions("wait_first_success() produced only errors");
    // retrieve up to 'count' results -- but stop there!
    for ( std::size_t i = 0; i < count; ++i) {
        // retrieve the next future
        future_t future( chanp->value_pop() );
        // retrieve exception_ptr if any
        std::exception_ptr error( future.get_exception_ptr() );
        // if no error, then yay, return value
        if ( ! error) {
            // close the channel: no subsequent push() has to succeed
            chanp->close();
            // show caller the value we got
            return future.get();
        }

        // error is non-null: collect
        exceptions.add( error);
    }
    // We only arrive here when every passed function threw an exception.
    // Throw our collection to inform caller.
    throw exceptions;
}
//]
//[wait_first_success_c
template< typename Fn >
typename std::result_of< Fn() >::type
wait_first_success_c( std::vector< Fn >&& functions) {
    std::size_t count( functions.size() );
    // In this case, the value we pass through the channel is actually a
    // future -- which is already ready. future can carry either a value or an
    // exception.
    typedef typename std::result_of< typename std::decay< Fn >::type() >::type return_t;
    typedef boost::fibers::future< return_t > future_t;
    typedef boost::fibers::buffered_channel< future_t > channel_t;
    auto chanp( std::make_shared< channel_t >( 64) );
    // launch all the relevant fibers
    for( auto&& f : functions) {
        wait_first_outcome_impl< return_t >( chanp, std::forward< Fn >( f) );
    }
    // instantiate exception_list, just in case
    exception_list exceptions("wait_first_success() produced only errors");
    // retrieve up to 'count' results -- but stop there!
    for ( std::size_t i = 0; i < count; ++i) {
        // retrieve the next future
        future_t future( chanp->value_pop() );
        // retrieve exception_ptr if any
        std::exception_ptr error( future.get_exception_ptr() );
        // if no error, then yay, return value
        if ( ! error) {
            // close the channel: no subsequent push() has to succeed
            chanp->close();
            // show caller the value we got
            return future.get();
        }

        // error is non-null: collect
        exceptions.add( error);
    }
    // We only arrive here when every passed function threw an exception.
    // Throw our collection to inform caller.
    throw exceptions;
}
//]


/*****************************************************************************
*   when_any, heterogeneous
*****************************************************************************/
//[wait_first_value_het
// No need to break out the first Fn for interface function: let the compiler
// complain if empty.
// Our functions have different return types, and we might have to return any
// of them. Use a variant, expanding std::result_of<Fn()>::type for each Fn in
// parameter pack.
template< typename ... Fns >
boost::variant< typename std::result_of< Fns() >::type ... >
wait_first_value_het( Fns && ... functions) {
    // Use buffered_channel<boost::variant<T1, T2, ...>>; see remarks above.
    typedef boost::variant< typename std::result_of< Fns() >::type ... > return_t;
    typedef boost::fibers::buffered_channel< return_t > channel_t;
    auto chanp( std::make_shared< channel_t >( 64) );
    // launch all the relevant fibers
    wait_first_value_impl< return_t >( chanp,
                                       std::forward< Fns >( functions) ... );
    // retrieve the first value
    return_t value( chanp->value_pop() );
    // close the channel: no subsequent push() has to succeed
    chanp->close();
    return value;
}
//]


/*****************************************************************************
*   when_all, simple completion
*****************************************************************************/
// Degenerate case: when there are no functions to wait for, return
// immediately.
inline void wait_all_simple_impl( std::shared_ptr< boost::fibers::barrier >) {
}

// When there's at least one function to wait for, launch it and recur to
// process the rest.
//[wait_all_simple_impl
template< typename Fn, typename ... Fns >
void wait_all_simple_impl( std::shared_ptr< boost::fibers::barrier > barrier,
                           Fn && function, Fns && ... functions) {
    boost::fibers::fiber(
            std::bind(
                []( std::shared_ptr< boost::fibers::barrier > & barrier,
                    typename std::decay< Fn >::type & function) mutable {
                        function();
                        barrier->wait();
                },
                barrier,
                std::forward< Fn >( function)
            )).detach();
    wait_all_simple_impl( barrier, std::forward< Fns >( functions) ... );
}
//]

// interface function: instantiate barrier, launch tasks, wait for barrier
//[wait_all_simple
template< typename ... Fns >
void wait_all_simple( Fns && ... functions) {
    std::size_t count( sizeof ... ( functions) );
    // Initialize a barrier(count+1) because we'll immediately wait on it. We
    // don't want to wake up until 'count' more fibers wait on it. Even though
    // we'll stick around until the last of them completes, use shared_ptr
    // anyway because it's easier to be confident about lifespan issues.
    auto barrier( std::make_shared< boost::fibers::barrier >( count + 1) );
    wait_all_simple_impl( barrier, std::forward< Fns >( functions) ... );
    barrier->wait();
}
//]
//[wait_all_simple_c
template< typename Fn >
void wait_all_simple_c( std::vector< Fn >&& functions) {
    std::size_t count = functions.size();
    // Initialize a barrier(count+1) because we'll immediately wait on it. We
    // don't want to wake up until 'count' more fibers wait on it. Even though
    // we'll stick around until the last of them completes, use shared_ptr
    // anyway because it's easier to be confident about lifespan issues.
    auto barrier( std::make_shared< boost::fibers::barrier >( count + 1) );
    for ( auto&& f : functions) {
        wait_all_simple_impl( barrier,  std::forward< Fn >( f) );
    }
    barrier->wait();
}
//]

/*****************************************************************************
*   when_all, return values
*****************************************************************************/
//[wait_nchannel
// Introduce a channel facade that closes the channel once a specific number
// of items has been pushed. This allows an arbitrary consumer to read until
// 'closed' without itself having to count items.
template< typename T >
class nchannel {
public:
    nchannel( std::shared_ptr< boost::fibers::buffered_channel< T > > chan,
              std::size_t lm):
        chan_( chan),
        limit_( lm) {
        assert(chan_);
        if ( 0 == limit_) {
            chan_->close();
        }
    }

    boost::fibers::channel_op_status push( T && va) {
        boost::fibers::channel_op_status ok =
            chan_->push( std::forward< T >( va) );
        if ( ok == boost::fibers::channel_op_status::success &&
             --limit_ == 0) {
            // after the 'limit_'th successful push, close the channel
            chan_->close();
        }
        return ok;
    }

private:
    std::shared_ptr< boost::fibers::buffered_channel< T > >    chan_;
    std::size_t                                                 limit_;
};
//]

// When there's only one function, call this overload
//[wait_all_values_impl
template< typename T, typename Fn >
void wait_all_values_impl( std::shared_ptr< nchannel< T > > chan,
                           Fn && function) {
    boost::fibers::fiber( [chan, function](){
                              chan->push(function());
                          }).detach();
}
//]

// When there are two or more functions, call this overload
template< typename T, typename Fn0, typename Fn1, typename ... Fns >
void wait_all_values_impl( std::shared_ptr< nchannel< T > > chan,
                           Fn0 && function0,
                           Fn1 && function1,
                           Fns && ... functions) {
    // process the first function using the single-function overload
    wait_all_values_impl< T >( chan, std::forward< Fn0 >( function0) );
    // then recur to process the rest
    wait_all_values_impl< T >( chan,
                               std::forward< Fn1 >( function1),
                               std::forward< Fns >( functions) ... );
}

//[wait_all_values_source
// Return a shared_ptr<buffered_channel<T>> from which the caller can
// retrieve each new result as it arrives, until 'closed'.
template< typename Fn, typename ... Fns >
std::shared_ptr< boost::fibers::buffered_channel< typename std::result_of< Fn() >::type > >
wait_all_values_source( Fn && function, Fns && ... functions) {
    std::size_t count( 1 + sizeof ... ( functions) );
    typedef typename std::result_of< Fn() >::type return_t;
    typedef boost::fibers::buffered_channel< return_t > channel_t;
    // make the channel
    auto chanp( std::make_shared< channel_t >( 64) );
    // and make an nchannel facade to close it after 'count' items
    auto ncp( std::make_shared< nchannel< return_t > >( chanp, count) );
    // pass that nchannel facade to all the relevant fibers
    wait_all_values_impl< return_t >( ncp,
                                      std::forward< Fn >( function),
                                      std::forward< Fns >( functions) ... );
    // then return the channel for consumer
    return chanp;
}
//]
//[wait_all_values_source_c
template< typename Fn >
std::shared_ptr< boost::fibers::buffered_channel< typename std::result_of< Fn() >::type > >
wait_all_values_source_c( std::vector< Fn >&& functions) {
    std::size_t count = functions.size();
    typedef typename std::result_of< Fn() >::type return_t;
    typedef boost::fibers::buffered_channel< return_t > channel_t;
    // make the channel
    auto chanp( std::make_shared< channel_t >( 64) );
    // and make an nchannel facade to close it after 'count' items
    auto ncp( std::make_shared< nchannel< return_t > >( chanp, count) );
    // pass that nchannel facade to all the relevant fibers
    for( auto&& f : functions) {
        wait_all_values_impl< return_t >( ncp, std::forward< Fn >( f) );
    }
    // then return the channel for consumer
    return chanp;
}
//]

// When all passed functions have completed, return vector<T> containing
// collected results. Assume that all passed functions have the same return
// type. It is simply invalid to pass NO functions.
//[wait_all_values
template< typename Fn, typename ... Fns >
std::vector< typename std::result_of< Fn() >::type >
wait_all_values( Fn && function, Fns && ... functions) {
    std::size_t count( 1 + sizeof ... ( functions) );
    typedef typename std::result_of< Fn() >::type return_t;
    typedef std::vector< return_t > vector_t;
    vector_t results;
    results.reserve( count);

    // get channel
    std::shared_ptr< boost::fibers::buffered_channel< return_t > > chan =
        wait_all_values_source( std::forward< Fn >( function),
                                std::forward< Fns >( functions) ... );
    // fill results vector
    return_t value;
    while ( boost::fibers::channel_op_status::success == chan->pop(value) ) {
        results.push_back( value);
    }
    // return vector to caller
    return results;
}
//]
//[wait_all_values
template< typename Fn >
std::vector< typename std::result_of< Fn() >::type >
wait_all_values_c( std::vector< Fn >&& functions) {
    std::size_t count = functions.size();
    typedef typename std::result_of< Fn() >::type return_t;
    typedef std::vector< return_t > vector_t;
    vector_t results;
    results.reserve( count);

    // get channel
    std::shared_ptr< boost::fibers::buffered_channel< return_t > > chan =
        wait_all_values_source_c( std::forward< std::vector< Fn > >(functions) );
    // fill results vector
    return_t value;
    while ( boost::fibers::channel_op_status::success == chan->pop(value) ) {
        results.push_back( value);
    }
    // return vector to caller
    return results;
}
//]


/*****************************************************************************
*   when_all, throw first exception
*****************************************************************************/
//[wait_all_until_error_source
// Return a shared_ptr<buffered_channel<future<T>>> from which the caller can
// get() each new result as it arrives, until 'closed'.
template< typename Fn, typename ... Fns >
std::shared_ptr<
    boost::fibers::buffered_channel<
        boost::fibers::future<
            typename std::result_of< Fn() >::type > > >
wait_all_until_error_source( Fn && function, Fns && ... functions) {
    std::size_t count( 1 + sizeof ... ( functions) );
    typedef typename std::result_of< Fn() >::type return_t;
    typedef boost::fibers::future< return_t > future_t;
    typedef boost::fibers::buffered_channel< future_t > channel_t;
    // make the channel
    auto chanp( std::make_shared< channel_t >( 64) );
    // and make an nchannel facade to close it after 'count' items
    auto ncp( std::make_shared< nchannel< future_t > >( chanp, count) );
    // pass that nchannel facade to all the relevant fibers
    wait_first_outcome_impl< return_t >( ncp,
                                         std::forward< Fn >( function),
                                         std::forward< Fns >( functions) ... );
    // then return the channel for consumer
    return chanp;
}
//]
//[wait_all_until_error_source_c
template< typename Fn >
std::shared_ptr<
    boost::fibers::buffered_channel<
        boost::fibers::future<
            typename std::result_of< Fn() >::type > > >
wait_all_until_error_source_c( std::vector< Fn >&& functions ) {
    std::size_t count = functions.size();
    typedef typename std::result_of< Fn() >::type return_t;
    typedef boost::fibers::future< return_t > future_t;
    typedef boost::fibers::buffered_channel< future_t > channel_t;
    // make the channel
    auto chanp( std::make_shared< channel_t >( 64) );
    // and make an nchannel facade to close it after 'count' items
    auto ncp( std::make_shared< nchannel< future_t > >( chanp, count) );
    // pass that nchannel facade to all the relevant fibers
    for(auto&& f : functions) {
        wait_first_outcome_impl< return_t >( ncp, std::forward< Fn >( f) );
    }

    // then return the channel for consumer
    return chanp;
}

// When all passed functions have completed, return vector<T> containing
// collected results, or throw the first exception thrown by any of the passed
// functions. Assume that all passed functions have the same return type. It
// is simply invalid to pass NO functions.
//[wait_all_until_error
template< typename Fn, typename ... Fns >
std::vector< typename std::result_of< Fn() >::type >
wait_all_until_error( Fn && function, Fns && ... functions) {
    std::size_t count( 1 + sizeof ... ( functions) );
    typedef typename std::result_of< Fn() >::type return_t;
    typedef typename boost::fibers::future< return_t > future_t;
    typedef std::vector< return_t > vector_t;
    vector_t results;
    results.reserve( count);

    // get channel
    std::shared_ptr<
        boost::fibers::buffered_channel< future_t > > chan(
            wait_all_until_error_source( std::forward< Fn >( function),
                                         std::forward< Fns >( functions) ... ) );
    // fill results vector
    future_t future;
    while ( boost::fibers::channel_op_status::success == chan->pop( future) ) {
        results.push_back( future.get() );
    }
    // return vector to caller
    return results;
}
//]
//[wait_all_until_error_c
template< typename Fn >
std::vector< typename std::result_of< Fn() >::type >
wait_all_until_error_c( std::vector< Fn >&& functions) {
    std::size_t count = functions.size();
    typedef typename std::result_of< Fn() >::type return_t;
    typedef typename boost::fibers::future< return_t > future_t;
    typedef std::vector< return_t > vector_t;
    vector_t results;
    results.reserve( count);

    // get channel
    std::shared_ptr<
        boost::fibers::buffered_channel< future_t > > chan(
            wait_all_until_error_source_c( std::forward< std::vector< Fn > >(functions) ) );
    // fill results vector
    future_t future;
    while ( boost::fibers::channel_op_status::success == chan->pop( future) ) {
        results.push_back( future.get() );
    }
    // return vector to caller
    return results;
}
//]

/*****************************************************************************
*   when_all, collect exceptions
*****************************************************************************/
// When all passed functions have succeeded, return vector<T> containing
// collected results, or throw exception_list containing all exceptions thrown
// by any of the passed functions. Assume that all passed functions have the
// same return type. It is simply invalid to pass NO functions.
//[wait_all_collect_errors
template< typename Fn, typename ... Fns >
std::vector< typename std::result_of< Fn() >::type >
wait_all_collect_errors( Fn && function, Fns && ... functions) {
    std::size_t count( 1 + sizeof ... ( functions) );
    typedef typename std::result_of< Fn() >::type return_t;
    typedef typename boost::fibers::future< return_t > future_t;
    typedef std::vector< return_t > vector_t;
    vector_t results;
    results.reserve( count);
    exception_list exceptions("wait_all_collect_errors() exceptions");

    // get channel
    std::shared_ptr<
        boost::fibers::buffered_channel< future_t > > chan(
            wait_all_until_error_source( std::forward< Fn >( function),
                                         std::forward< Fns >( functions) ... ) );
    // fill results and/or exceptions vectors
    future_t future;
    while ( boost::fibers::channel_op_status::success == chan->pop( future) ) {
        std::exception_ptr exp = future.get_exception_ptr();
        if ( ! exp) {
            results.push_back( future.get() );
        } else {
            exceptions.add( exp);
        }
    }
    // if there were any exceptions, throw
    if ( exceptions.size() ) {
        throw exceptions;
    }
    // no exceptions: return vector to caller
    return results;
}
//]

//[wait_all_collect_errors_c
template< typename Fn >
std::vector< typename std::result_of< Fn() >::type >
wait_all_collect_errors_c( std::vector< Fn >&& functions) {
    std::size_t count = functions.size();
    typedef typename std::result_of< Fn() >::type return_t;
    typedef typename boost::fibers::future< return_t > future_t;
    typedef std::vector< return_t > vector_t;
    vector_t results;
    results.reserve( count);
    exception_list exceptions("wait_all_collect_errors() exceptions");

    // get channel
    std::shared_ptr<
        boost::fibers::buffered_channel< future_t > > chan(
            wait_all_until_error_source_c( std::forward< std::vector< Fn > >(functions) ) );
    // fill results and/or exceptions vectors
    future_t future;
    while ( boost::fibers::channel_op_status::success == chan->pop( future) ) {
        std::exception_ptr exp = future.get_exception_ptr();
        if ( ! exp) {
            results.push_back( future.get() );
        } else {
            exceptions.add( exp);
        }
    }
    // if there were any exceptions, throw
    if ( exceptions.size() ) {
        throw exceptions;
    }
    // no exceptions: return vector to caller
    return results;
}
//]

/*****************************************************************************
*   when_all, heterogeneous
*****************************************************************************/
//[wait_all_members_get
template< typename Result, typename ... Futures >
Result wait_all_members_get( Futures && ... futures) {
    // Fetch the results from the passed futures into Result's initializer
    // list. It's true that the get() calls here will block the implicit
    // iteration over futures -- but that doesn't matter because we won't be
    // done until the slowest of them finishes anyway. As results are
    // processed in argument-list order rather than order of completion, the
    // leftmost get() to throw an exception will cause that exception to
    // propagate to the caller.
    return Result{ futures.get() ... };
}
//]

//[wait_all_members
// Explicitly pass Result. This can be any type capable of being initialized
// from the results of the passed functions, such as a struct.
template< typename Result, typename ... Fns >
Result wait_all_members( Fns && ... functions) {
    // Run each of the passed functions on a separate fiber, passing all their
    // futures to helper function for processing.
    return wait_all_members_get< Result >(
            boost::fibers::async( std::forward< Fns >( functions) ) ... );
}
//]

#endif
