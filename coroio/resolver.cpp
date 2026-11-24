#include "resolver.hpp"
#include "socket.hpp"
#include "sockutils.hpp"
#include "promises.hpp"
#ifdef __linux__
#include "uring.hpp"
#endif
#include <charconv>
#include <string_view>
#include <utility>
#include <fstream>

namespace NNet {

namespace {

// Based on https://w3.cs.jmu.edu/kirkpams/OpenCSF/Books/csf/html/UDPSockets.html

struct TDnsHeader {
    uint16_t xid = 0;      /* Randomly chosen identifier */
    uint16_t flags = 0;    /* Bit-mask to indicate request/response */
    uint16_t qdcount = 0;  /* Number of questions */
    uint16_t ancount = 0;  /* Number of answers */
    uint16_t nscount = 0;  /* Number of authority records */
    uint16_t arcount = 0;  /* Number of additional records */
} __attribute__((__packed__));

struct TDnsRecordA {
    uint16_t type;
    uint16_t clazz;
    uint32_t ttl;
    uint16_t length;
//    char addr[0];
} __attribute__((packed));

static_assert(sizeof(TDnsRecordA) == 10);

} // namespace

std::string TDetail::EncodeDnsName(std::string_view name) {
    if (name.empty()) throw std::invalid_argument("DNS name cannot be empty");
    if (name == ".") return std::string(1, '\0');

    const auto nameEnd = name.back() == '.' ? name.size() - 1 : name.size();
    if (!nameEnd) throw std::invalid_argument("DNS name has no labels");

    std::string encoded;
    size_t labelStart = 0;
    for (size_t i = 0; i <= nameEnd; ++i) {
        if (i != nameEnd && name[i] != '.') {
            const auto ch = static_cast<unsigned char>(name[i]);
            if (ch <= 0x20 || ch == 0x7f)
                throw std::invalid_argument("DNS name contains whitespace or a control character");
            continue;
        }

        const auto labelBytes = i - labelStart;
        if (!labelBytes || labelBytes > 63)
            throw std::invalid_argument("DNS labels must contain between 1 and 63 bytes");
        if (encoded.size() > 253 || labelBytes > 253 - encoded.size())
            throw std::invalid_argument("DNS name exceeds the 255-byte wire limit");
        encoded.push_back(static_cast<char>(labelBytes));
        encoded.append(name.substr(labelStart, labelBytes));
        labelStart = i + 1;
    }
    encoded.push_back('\0');
    return encoded;
}

namespace {

void CreatePacket(std::string_view name, EDNSType type, char* packet,
        size_t capacity, int* size, uint16_t xid) {
    const auto encodedName = TDetail::EncodeDnsName(name);
    const size_t packetlen = sizeof(TDnsHeader) + encodedName.size() + 2 * sizeof(uint16_t);
    if (packetlen > capacity)
        throw std::invalid_argument("DNS query exceeds its packet buffer");

    TDnsHeader header = {
        .xid = htons(xid),
        .flags = htons(0x0100), /* Q=0, RD=1 */
        .qdcount = htons(1) /* Sending 1 question */
    };

    auto* p = reinterpret_cast<uint8_t*>(packet);
    std::memcpy(p, &header, sizeof(header));
    p += sizeof(header);
    std::memcpy(p, encodedName.data(), encodedName.size());
    p += encodedName.size();
    const auto queryType = htons(static_cast<uint16_t>(type));
    const auto queryClass = htons(uint16_t(1));
    std::memcpy(p, &queryType, sizeof(queryType));
    p += sizeof(queryType);
    std::memcpy(p, &queryClass, sizeof(queryClass));
    *size = static_cast<int>(packetlen);
}

void ParsePacket(uint16_t* xid, std::vector<TAddress>& addresses, char* buf, ssize_t size) {
    TDnsHeader* header = (TDnsHeader*)(&buf[0]);
    *xid = ntohs(header->xid);
    if ((ntohs (header->flags) & 0xf) != 0) {
        throw std::runtime_error("Resolver Error");
    }
    uint8_t* startOfName = (uint8_t*)(&buf[0] + sizeof (TDnsHeader));
    uint8_t fragmentSize = 0;
    uint8_t* p = startOfName; size -= p - (uint8_t*)buf; if (size <= 0) { throw std::runtime_error("Not enough data"); }

    while (*p != 0)
    {
        /* Restore the dot in the name and advance to next length */
        fragmentSize = *p + 1;
        *p = '.';
        p += fragmentSize; size -= fragmentSize; if (size <= 0) { throw std::runtime_error("Not enough data"); }
    }

    addresses.reserve(ntohs(header->ancount));
    if (ntohs(header->ancount) == 0) {
        return;
    }
    p += 5; size -= 5; if (size <= 0) { throw std::runtime_error("Not enough data"); }
    for (int i = 0; i < ntohs (header->ancount); i++)
    {
        uint16_t* compression = (uint16_t*)p; p += 2; size -= 2; if (size <= 0) { throw std::runtime_error("Not enough data"); }
        if (! ((ntohs(*compression) & 0xC000) == 0xC000)) {
            // skip full name
            while (*p) {
                p++; size--; if (size <= 0) { throw std::runtime_error("Not enough data"); }
            }
            p++; size--; if (size <= 0) { throw std::runtime_error("Not enough data"); }
        }

        TDnsRecordA* record = (TDnsRecordA*)p;

        auto addrLen = ntohs(record->length);
        if (addrLen == 4) {
            sockaddr_in addr;
            addr.sin_port = 0,
            addr.sin_addr = *(in_addr*)(record+1);
            addresses.emplace_back(TAddress{addr});
        } else if (addrLen == 16) {
            sockaddr_in6 addr;
            addr.sin6_port = 0,
            addr.sin6_addr = *(in6_addr*)(record+1);
            addresses.emplace_back(TAddress{addr});
        }
        p += sizeof(TDnsRecordA);
        p += addrLen;
        size -= sizeof(TDnsRecordA); size -= addrLen; if (size < 0) { throw std::runtime_error("Not enough data"); }
    }
}

bool IsValidHostText(std::string_view host) {
    if (host.empty()) return false;
    for (unsigned char ch : host) {
        if (ch <= 0x20 || ch == 0x7f || ch == '[' || ch == ']') return false;
    }
    return true;
}

bool IsIpv6Literal(std::string_view host) {
    const std::string value(host);
    in6_addr address{};
    return inet_pton(AF_INET6, value.c_str(), &address) == 1;
}

void ValidateHost(std::string_view host) {
    if (!IsValidHostText(host) ||
        (host.find(':') != std::string_view::npos && !IsIpv6Literal(host)))
        throw std::invalid_argument("Invalid host name or address");
    if (host.find(':') == std::string_view::npos)
        (void)TDetail::EncodeDnsName(host);
}

int ParsePort(std::string_view portText) {
    if (portText.empty())
        throw std::invalid_argument("Port must be an integer from 1 through 65535");
    uint32_t port = 0;
    const auto result = std::from_chars(portText.data(), portText.data() + portText.size(), port);
    if (result.ec != std::errc{} || result.ptr != portText.data() + portText.size() ||
        port == 0 || port > 65535)
        throw std::invalid_argument("Port must be an integer from 1 through 65535");
    return static_cast<int>(port);
}

} // namespace

TResolvConf::TResolvConf(const std::string& fn)
{
    std::ifstream input(fn);
    Load(input);
}

TResolvConf::TResolvConf(std::istream& input) {
    Load(input);
}

void TResolvConf::Load(std::istream& input) {
    for (std::string line; getline(input, line);) {
        std::vector<std::string> tokens;
        const char* sep = " ";
        for (char* tok = strtok(line.data(), sep); tok; tok = strtok(nullptr, sep)) {
            tokens.push_back(tok);
        }
        if (tokens.size() == 2 && tokens[0] == "nameserver") {
            auto addr = TAddress{tokens[1], 53};
            Nameservers.emplace_back(std::move(addr));
        }
    }

    if (Nameservers.empty()) {
        Nameservers.emplace_back(TAddress{"127.0.0.1", 53});
    }
}

template<typename TPoller>
TResolver<TPoller>::TResolver(TPoller& poller, EDNSType defaultType)
    : TResolver(TResolvConf(), poller, defaultType)
{ }

template<typename TPoller>
TResolver<TPoller>::TResolver(const TResolvConf& conf, TPoller& poller, EDNSType defaultType)
    : TResolver(conf.Nameservers[0], poller, defaultType)
{ }

template<typename TPoller>
TResolver<TPoller>::TResolver(TAddress dnsAddr, TPoller& poller, EDNSType defaultType)
    : Socket(std::move(dnsAddr), poller, SOCK_DGRAM)
    , Poller(poller)
    , DefaultType(defaultType)
{
    // Start tasks after fields initialization
    Sender = SenderTask();
    Receiver = ReceiverTask();
    Timeouts = TimeoutsTask();
}

template<typename TPoller>
TFuture<void> TResolver<TPoller>::SenderTask() {
    co_await Socket.Connect();
    char buf[512];
    while (true) {
        while (AddResolveQueue.empty()) {
            SenderSuspended = co_await Self();
            co_await std::suspend_always{};
        }
        SenderSuspended = {};
        auto req = AddResolveQueue.front(); AddResolveQueue.pop();
        int len;
        memset(buf, 0, sizeof(buf));
        CreatePacket(req.Name, req.Type, buf, sizeof(buf), &len, Xid);
        Inflight[Xid] = req;
        Xid = 1 + (Xid + 1) % 65535;
        co_await TByteWriter(Socket).Write(buf, len);
    }
    co_return;
}

template<typename TPoller>
TFuture<void> TResolver<TPoller>::TimeoutsTask() {
    while (true) {
        TTime now = TClock::now();
        while (!TimeoutsQueue.empty() && TimeoutsQueue.front().first <= now) {
            auto req = std::move(TimeoutsQueue.front().second);
            ResumeWaiters({.Exception = std::make_exception_ptr(std::runtime_error("Timeout"))}, req);
            TimeoutsQueue.pop();
        }
        co_await Poller.Sleep(now + std::chrono::milliseconds(100));
    }
}

template<typename TPoller>
void TResolver<TPoller>::ResumeWaiters(TResolveResult&& result, const TResolveRequest& req) {
    auto maybeWaiting = WaitingAddrs.find(req);
    if (maybeWaiting != WaitingAddrs.end()) {
        Results[req] = std::move(result);
        auto handles = std::move(maybeWaiting->second);
        WaitingAddrs.erase(maybeWaiting);
        for (auto h : handles) {
            h.resume();
        }
    }
}

template<typename TPoller>
TFuture<void> TResolver<TPoller>::ReceiverTask() {
    char buf[512];
    while (true) {
        auto size = co_await Socket.ReadSome(buf, sizeof(buf));
        if (size < 0) {
            continue;
        }
        if (size < static_cast<int>(sizeof(TDnsHeader))) {
            continue;
        }

        std::vector<TAddress> addresses;
        std::exception_ptr exception;
        uint16_t xid;
        try {
            ParsePacket(&xid, addresses, buf, size);
        } catch (const std::exception& ex) {
            exception = std::current_exception();
        }

        ResumeWaiters(std::move(TResolveResult {
            .Addresses = std::move(addresses),
            .Exception = exception
        }), Inflight[xid]);
    }
    co_return;
}

template<typename TPoller>
void TResolver<TPoller>::ResumeSender() {
    if (SenderSuspended) {
        SenderSuspended.resume();
    }
}

template<typename TPoller>
TValueTask<std::vector<TAddress>> TResolver<TPoller>::Resolve(const std::string& hostname, EDNSType type) {
    (void)TDetail::EncodeDnsName(hostname);
    auto handle = co_await Self();
    if (type == EDNSType::DEFAULT) {
        type = DefaultType;
    }

    TResolveRequest req = {.Name = hostname, .Type = type};

    if (!WaitingAddrs.contains(req)) {
        Results[req].Retries = 5;
        AddResolveQueue.emplace(req);
        TimeoutsQueue.emplace(std::make_pair(TClock::now() + std::chrono::milliseconds(2000), req));
    }
    WaitingAddrs[req].emplace_back(handle);
    ResumeSender();
    co_await std::suspend_always{};
    auto& result = Results[req];
    if (result.Exception) {
        std::rethrow_exception(result.Exception);
    }
    co_return result.Addresses;
}

THostPort::THostPort(const std::string& hostPort) {
    const std::string_view input(hostPort);
    std::string_view host;
    std::string_view portText;
    if (!input.empty() && input.front() == '[') {
        const auto close = input.find(']');
        if (close == std::string_view::npos || close == 1 || close + 1 >= input.size() ||
            input[close + 1] != ':')
            throw std::invalid_argument("Bracketed IPv6 endpoint must be [address]:port");
        host = input.substr(1, close - 1);
        if (!IsIpv6Literal(host))
            throw std::invalid_argument("Bracketed endpoint host must be an IPv6 literal");
        portText = input.substr(close + 2);
    } else {
        const auto separator = input.rfind(':');
        if (separator == std::string_view::npos || separator == 0)
            throw std::invalid_argument("Endpoint must be host:port");
        host = input.substr(0, separator);
        portText = input.substr(separator + 1);
    }
    ValidateHost(host);
    const auto port = ParsePort(portText);
    Host.assign(host);
    Port = port;
}

THostPort::THostPort(const std::string& host, int port)
    : Host(host)
    , Port(port)
{
    ValidateHost(Host);
    if (Port < 1 || Port > 65535)
        throw std::invalid_argument("Port must be an integer from 1 through 65535");
}

template<typename T>
TFuture<TAddress> THostPort::Resolve(TResolver<T>& resolver) {
    char buf[16];
    if (inet_pton(AF_INET, Host.c_str(), buf) == 1 || inet_pton(AF_INET6, Host.c_str(), buf)) {
        co_return TAddress{Host, Port};
    }

    auto addresses = co_await resolver.Resolve(Host);
    if (addresses.empty()) {
        throw std::runtime_error("Empty address");
    }

    co_return addresses.front().WithPort(Port);
}

template class TResolver<TPollerBase>;
template TFuture<TAddress> THostPort::Resolve(TResolver<TPollerBase>&);
#ifdef __linux__
template class TResolver<TUring>;
#endif

} // namespace NNet
