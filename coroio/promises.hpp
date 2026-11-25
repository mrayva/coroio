#pragma once
#include <atomic>
#include <coroutine>
#include <cstdio>
#include <exception>

namespace NNet {

using TUnhandledCoroutineExceptionHandler = void (*)(std::exception_ptr) noexcept;

inline void ReportUnhandledCoroutineExceptionToStderr(std::exception_ptr error) noexcept {
    try {
        std::rethrow_exception(error);
    } catch (const std::exception& ex) {
        std::fprintf(stderr, "Unhandled background coroutine exception: %s\n", ex.what());
    } catch (...) {
        std::fputs("Unhandled non-standard background coroutine exception\n", stderr);
    }
}

inline std::atomic<TUnhandledCoroutineExceptionHandler>& UnhandledCoroutineExceptionHandlerSlot() noexcept {
    static std::atomic<TUnhandledCoroutineExceptionHandler> handler{
        &ReportUnhandledCoroutineExceptionToStderr};
    return handler;
}

// The callback may run on any coroutine-resuming thread and must not throw.
// Passing nullptr restores the default stderr reporter.
inline TUnhandledCoroutineExceptionHandler SetUnhandledCoroutineExceptionHandler(
        TUnhandledCoroutineExceptionHandler handler) noexcept {
    if (!handler) handler = &ReportUnhandledCoroutineExceptionToStderr;
    return UnhandledCoroutineExceptionHandlerSlot().exchange(handler, std::memory_order_acq_rel);
}

inline void ReportUnhandledCoroutineException(std::exception_ptr error) noexcept {
    UnhandledCoroutineExceptionHandlerSlot().load(std::memory_order_acquire)(std::move(error));
}

struct TVoidPromise;

struct TVoidTask : std::coroutine_handle<TVoidPromise>
{
    using promise_type = TVoidPromise;
};

struct TVoidPromise
{
    TVoidTask get_return_object() { return { TVoidTask::from_promise(*this) }; }
    std::suspend_never initial_suspend() { return {}; }
    std::suspend_never final_suspend() noexcept { return {}; }
    void return_void() {}
    void unhandled_exception() noexcept {
        ReportUnhandledCoroutineException(std::current_exception());
    }
};

struct TVoidSuspendedPromise;

struct TVoidSuspendedTask : std::coroutine_handle<TVoidSuspendedPromise>
{
    using promise_type = TVoidSuspendedPromise;
};

struct TVoidSuspendedPromise
{
    TVoidSuspendedTask get_return_object() { return { TVoidSuspendedTask::from_promise(*this) }; }
    std::suspend_never initial_suspend() { return {}; }
    std::suspend_always final_suspend() noexcept { return {}; }
    void return_void() {}
    void unhandled_exception() noexcept {
        ReportUnhandledCoroutineException(std::current_exception());
    }
};

struct Self {
    bool await_ready() {
        return false;
    }

    bool await_suspend(std::coroutine_handle<> h) {
        H = h;
        return false;
    }

    auto await_resume() noexcept {
        return H;
    }

    std::coroutine_handle<> H;
};

} // namespace NNet
