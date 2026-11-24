#pragma once

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <exception>
#include <stdexcept>
#include <functional>

#include "base.hpp"
#include "corochain.hpp"
#include "sockutils.hpp"
#include "promises.hpp"

namespace NNet {

struct TSslContext {
    SSL_CTX* Ctx;
    std::function<void(const char*)> LogFunc = {};

    TSslContext(TSslContext&& other)
        : Ctx(other.Ctx)
        , LogFunc(other.LogFunc)
    {
        other.Ctx = nullptr;
    }

    ~TSslContext();

    static TSslContext Client(const std::function<void(const char*)>& logFunc = {});
    static TSslContext Server(const char* certfile, const char* keyfile, const std::function<void(const char*)>& logFunc = {});
    static TSslContext ServerFromMem(const void* certfile, const void* keyfile, const std::function<void(const char*)>& logFunc = {});

private:
    TSslContext();
};

template<typename THandle>
class TSslSocket {
public:
    using TPoller = typename THandle::TPoller;

    TSslSocket(THandle&& socket, TSslContext& ctx)
        : Socket(std::move(socket))
        , Ctx(&ctx)
        , Ssl(SSL_new(Ctx->Ctx))
        , Rbio(BIO_new(BIO_s_mem()))
        , Wbio(BIO_new(BIO_s_mem()))
    {
        SSL_set_bio(Ssl, Rbio, Wbio);
        SSL_set_mode(Ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
        SSL_set_mode(Ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    }

    TSslSocket(TSslSocket&& other)
    {
        *this = std::move(other);
    }

    TSslSocket& operator=(TSslSocket&& other) {
        if (this != &other) {
            const auto hasPendingHandshake = [](const TSslSocket& socket) {
                return (socket.Handshake && !socket.Handshake.done()) || !socket.Waiters.empty();
            };
            if (hasPendingHandshake(*this) || hasPendingHandshake(other)) {
                throw std::logic_error("Cannot move-assign a TLS socket with a pending handshake");
            }

            if (Handshake) Handshake.destroy();
            if (Ssl) SSL_free(Ssl);

            Socket = std::move(other.Socket);
            Ctx = other.Ctx;
            Ssl = other.Ssl;
            Rbio = other.Rbio;
            Wbio = other.Wbio;
            Handshake = other.Handshake;
            HandshakeFinished = other.HandshakeFinished;
            HandshakeError = std::move(other.HandshakeError);
            Waiters = std::move(other.Waiters);
            LastState = other.LastState;
            other.Ctx = nullptr;
            other.Ssl = nullptr;
            other.Rbio = other.Wbio = nullptr;
            other.Handshake = nullptr;
            other.HandshakeFinished = false;
            other.HandshakeError = nullptr;
            other.LastState = nullptr;
        }
        return *this;
    }

    TSslSocket(const TSslSocket& ) = delete;
    TSslSocket& operator=(const TSslSocket&) = delete;

    TSslSocket() = default;

    ~TSslSocket()
    {
        if (Ssl) { SSL_free(Ssl); }
        if (Handshake) { Handshake.destroy(); }
    }

    TValueTask<TSslSocket<THandle>> Accept() {
        auto underlying = std::move(co_await Socket.Accept());
        auto socket = TSslSocket(std::move(underlying), *Ctx);
        SSL_set_accept_state(socket.Ssl);
        co_return std::move(socket);
    }

    TValueTask<void> AcceptHandshake() {
        assert(!Handshake);
        SSL_set_accept_state(Ssl);
        co_return co_await DoHandshake();
    }

    TValueTask<void> Connect(TTime deadline = TTime::max()) {
        assert(!Handshake);
        co_await Socket.Connect(deadline);
        SSL_set_connect_state(Ssl);
        co_return co_await DoHandshake(deadline);
    }

    TValueTask<ssize_t> ReadSome(void* data, size_t size) {
        co_await WaitHandshake();

        while (true) {
            const int n = SSL_read(Ssl, data, size);
            const int status = n > 0 ? SSL_ERROR_NONE : SSL_get_error(Ssl, n);
            if (n > 0) {
                co_await DoIO(SSL_ERROR_NONE);
                co_return n;
            }

            if (status == SSL_ERROR_WANT_READ || status == SSL_ERROR_WANT_WRITE) {
                co_await DoIO(status);
                continue;
            }

            co_await DoIO(status);
            if (status == SSL_ERROR_ZERO_RETURN) {
                co_return 0;
            }
            throw std::runtime_error("SSL read error: " + std::to_string(status));
        }
    }

    TValueTask<ssize_t> WriteSome(const void* data, size_t size) {
        co_await WaitHandshake();

        auto r = size;
        const char* p = (const char*)data;
        while (size != 0) {
            auto n = SSL_write(Ssl, p, size);
            if (n <= 0) {
                const auto status = SSL_get_error(Ssl, n);
                if (status == SSL_ERROR_WANT_READ || status == SSL_ERROR_WANT_WRITE) {
                    co_await DoIO(status);
                    continue;
                }
                co_await DoIO(status);
                throw std::runtime_error("SSL write error: " + std::to_string(status));
            }

            co_await DoIO(SSL_ERROR_NONE);

            size -= n;
            p += n;
        }
        co_return r;
    }

    auto Poller() {
        return Socket.Poller();
    }

private:
    TValueTask<void> WriteTransport(const void* data, size_t size, TTime deadline) {
        const char* p = static_cast<const char*>(data);
        while (size != 0) {
            ssize_t written;
            if constexpr (requires(THandle& socket, const char* buffer, size_t length, TTime until) {
                    socket.WriteSome(buffer, length, until);
                }) {
                written = co_await Socket.WriteSome(p, size, deadline);
            } else {
                if (deadline != TTime::max()) {
                    throw std::system_error(std::make_error_code(std::errc::operation_not_supported),
                        "TLS transport does not support deadline-aware writes");
                }
                written = co_await Socket.WriteSome(p, size);
            }
            if (written == 0) throw std::runtime_error("Connection closed");
            if (written < 0) continue;
            p += written;
            size -= size_t(written);
        }
        co_return;
    }

    TValueTask<ssize_t> ReadTransport(void* data, size_t size, TTime deadline) {
        while (true) {
            ssize_t read;
            if constexpr (requires(THandle& socket, void* buffer, size_t length, TTime until) {
                    socket.ReadSome(buffer, length, until);
                }) {
                read = co_await Socket.ReadSome(data, size, deadline);
            } else {
                if (deadline != TTime::max()) {
                    throw std::system_error(std::make_error_code(std::errc::operation_not_supported),
                        "TLS transport does not support deadline-aware reads");
                }
                read = co_await Socket.ReadSome(data, size);
            }
            if (read >= 0) co_return read;
        }
    }

    TValueTask<void> DoIO(int sslStatus, TTime deadline = TTime::max()) {
        char buf[1024];
        int n;
        while ((n = BIO_read(Wbio, buf, sizeof(buf))) > 0) {
            co_await WriteTransport(buf, size_t(n), deadline);
        }
        if (n < 0 && !BIO_should_retry(Wbio)) {
            throw std::runtime_error("Cannot read Wbio");
        }

        if (sslStatus == SSL_ERROR_WANT_READ) {
            auto size = co_await ReadTransport(buf, sizeof(buf), deadline);
            if (size == 0) {
                throw std::runtime_error("Connection closed");
            }
            const char* p = buf;
            while (size != 0) {
                auto n = BIO_write(Rbio, p, size);
                if (n <= 0) {
                    throw std::runtime_error("Cannot write Rbio");
                }
                size -= n;
                p += n;
            }
        }

        co_return;
    }

    TValueTask<void> DoHandshake(TTime deadline = TTime::max()) {
        int r;
        LogState();
        while ((r = SSL_do_handshake(Ssl)) != 1) {
            LogState();
            int status = SSL_get_error(Ssl, r);
            if (status == SSL_ERROR_WANT_READ || status == SSL_ERROR_WANT_WRITE) {
                co_await DoIO(status, deadline);
            } else {
                throw std::runtime_error("SSL error: " + std::to_string(r));
            }
        }

        LogState();

        co_await DoIO(SSL_ERROR_NONE, deadline);

        if (Ctx->LogFunc) {
            Ctx->LogFunc("SSL Handshake established\n");
        }

        co_return;
    }

    void StartHandshake() {
        assert(!Handshake);
        HandshakeFinished = false;
        HandshakeError = nullptr;
        Handshake = RunHandshake();
    }

    TVoidSuspendedTask RunHandshake() {
        try {
            co_await DoHandshake();
        } catch (...) {
            HandshakeError = std::current_exception();
        }

        HandshakeFinished = true;
        auto waiters = std::move(Waiters);
        Waiters.clear();
        for (auto waiter : waiters) {
            if (waiter) waiter.resume();
        }
        co_return;
    }

    auto WaitHandshake() {
        if (!SSL_is_init_finished(Ssl) && !Handshake) {
            StartHandshake();
        }
        struct TAwaitable {
            bool await_ready() {
                return *finished || !handshake || handshake.done();
            }

            void await_suspend(std::coroutine_handle<> h) {
                waiters->push_back(h);
            }

            void await_resume() {
                if (*error) std::rethrow_exception(*error);
            }

            std::coroutine_handle<> handshake;
            std::vector<std::coroutine_handle<>>* waiters;
            bool* finished;
            std::exception_ptr* error;
        };

        return TAwaitable { Handshake, &Waiters, &HandshakeFinished, &HandshakeError };
    };

    void LogState() {
        if (!Ctx->LogFunc) return;

        char buf[1024];

        const char * state = SSL_state_string_long(Ssl);
        if (state != LastState) {
            if (state) {
                snprintf(buf, sizeof(buf), "SSL-STATE: %s", state);
                Ctx->LogFunc(buf);
            }
            LastState = state;
        }
    }

    THandle Socket;
    TSslContext* Ctx = nullptr;

    SSL* Ssl = nullptr;
    BIO* Rbio = nullptr;
    BIO* Wbio = nullptr;

    const char* LastState = nullptr;

    std::coroutine_handle<> Handshake;
    bool HandshakeFinished = false;
    std::exception_ptr HandshakeError;
    std::vector<std::coroutine_handle<>> Waiters;
};

} // namespace NNet
