#include "ssl.hpp"
#include <stdexcept>
#include <assert.h>

namespace NNet {

namespace {

void LoadTlsIdentity(SSL_CTX* context, const char* certFile, const char* keyFile) {
    if (!certFile || !*certFile || !keyFile || !*keyFile)
        throw std::invalid_argument("TLS certificate and key paths are required");
    if (SSL_CTX_use_certificate_chain_file(context, certFile) != 1)
        throw std::runtime_error("Cannot load TLS certificate chain");
    if (SSL_CTX_use_PrivateKey_file(context, keyFile, SSL_FILETYPE_PEM) != 1)
        throw std::runtime_error("Cannot load TLS private key");
    if (SSL_CTX_check_private_key(context) != 1)
        throw std::runtime_error("TLS certificate and private key do not match");
}

void LoadTrustStore(SSL_CTX* context, const char* trustedCaFile) {
    if (!trustedCaFile || !*trustedCaFile)
        throw std::invalid_argument("TLS trusted CA path is required");
    if (SSL_CTX_load_verify_locations(context, trustedCaFile, nullptr) != 1)
        throw std::runtime_error("Cannot load TLS trusted CA file");
}

} // namespace

TSslContext::TSslContext() {
    static int init = 0;
    if (!init) {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ERR_load_crypto_strings();
        init = 1;
    }
}

TSslContext::~TSslContext() {
    SSL_CTX_free(Ctx);
}

TSslContext TSslContext::Client(const std::function<void(const char*)>& logFunc) {
    TSslContext ctx;
    ctx.Ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_options(ctx.Ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
    ctx.LogFunc = logFunc;
    return ctx;
}

TSslContext TSslContext::Server(const char* certfile, const char* keyfile, const std::function<void(const char*)>& logFunc) {
    TSslContext ctx;
    ctx.Ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_options(ctx.Ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
    ctx.LogFunc = logFunc;

    if (SSL_CTX_use_certificate_file(ctx.Ctx, certfile,  SSL_FILETYPE_PEM) != 1) {
        throw std::runtime_error("SSL_CTX_use_certificate_file failed");
    }

    if (SSL_CTX_use_PrivateKey_file(ctx.Ctx, keyfile, SSL_FILETYPE_PEM) != 1) {
        throw std::runtime_error("SSL_CTX_use_PrivateKey_file failed");
    }

    if (SSL_CTX_check_private_key(ctx.Ctx) != 1) {
        throw std::runtime_error("SSL_CTX_check_private_key failed");
    }

    return ctx;
}

TSslContext TSslContext::ServerFromMem(const void* certMem, const void* keyMem, const std::function<void(const char*)>& logFunc) {
    TSslContext ctx;
    ctx.Ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_options(ctx.Ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
    ctx.LogFunc = logFunc;

    auto cbio = std::shared_ptr<BIO>(BIO_new_mem_buf(certMem, -1), BIO_free);
    auto cert = std::shared_ptr<X509>(PEM_read_bio_X509(cbio.get(), NULL, 0, nullptr), X509_free);
    if (!cert) {
        throw std::runtime_error("Cannot load X509 certificate");
    }
    SSL_CTX_use_certificate(ctx.Ctx, cert.get());

    auto kbio = std::shared_ptr<BIO>(BIO_new_mem_buf(keyMem, -1), BIO_free);
    auto key = std::shared_ptr<EVP_PKEY>(PEM_read_bio_PrivateKey(kbio.get(), NULL, 0, nullptr), EVP_PKEY_free);
    if (!key) {
        throw std::runtime_error("Cannot load Key");
    }
    SSL_CTX_use_PrivateKey(ctx.Ctx, key.get());

    return ctx;
}

TSslContext TSslContext::MutualTlsClient(const char* trustedCaFile,
        const char* certFile, const char* keyFile,
        const std::function<void(const char*)>& logFunc) {
    TSslContext ctx;
    ctx.Ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx.Ctx) throw std::runtime_error("SSL_CTX_new failed for TLS client");
    SSL_CTX_set_options(ctx.Ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    ctx.LogFunc = logFunc;
    LoadTrustStore(ctx.Ctx, trustedCaFile);
    LoadTlsIdentity(ctx.Ctx, certFile, keyFile);
    SSL_CTX_set_verify(ctx.Ctx, SSL_VERIFY_PEER, nullptr);
    return ctx;
}

TSslContext TSslContext::MutualTlsServer(const char* certFile, const char* keyFile,
        const char* trustedCaFile,
        const std::function<void(const char*)>& logFunc) {
    TSslContext ctx;
    ctx.Ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx.Ctx) throw std::runtime_error("SSL_CTX_new failed for TLS server");
    SSL_CTX_set_options(ctx.Ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    ctx.LogFunc = logFunc;
    LoadTlsIdentity(ctx.Ctx, certFile, keyFile);
    LoadTrustStore(ctx.Ctx, trustedCaFile);
    SSL_CTX_set_verify(ctx.Ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    return ctx;
}

} // namespace NNet
