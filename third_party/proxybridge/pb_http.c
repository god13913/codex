#include "pb_internal.h"

#define HTTP_CONNECT_HEADER_LIMIT 16384
#define HTTP_CONNECT_TIMEOUT_MS 10000

// One absolute budget covers sending and receiving, even for a dribbling peer.
static BOOL http_remaining_timeout(SOCKET s, int option, ULONGLONG deadline)
{
    ULONGLONG now = GetTickCount64();
    if (now >= deadline) { WSASetLastError(WSAETIMEDOUT); return FALSE; }
    DWORD remaining = (DWORD)(deadline - now);
    return setsockopt(s, SOL_SOCKET, option, (const char *)&remaining, sizeof(remaining)) == 0;
}

static int http_connect_request(SOCKET s, const char *host, UINT16 port, const PROXY_CONFIG *cfg)
{
    char request[2048], response[HTTP_CONNECT_HEADER_LIMIT];
    char auth[HTTP_BUFFER_SIZE] = "";
    int length;
    if (cfg && cfg->username[0]) {
        char credentials[SOCKS5_BUFFER_SIZE], encoded[HTTP_BUFFER_SIZE];
        length = snprintf(credentials, sizeof(credentials), "%s:%s", cfg->username, cfg->password);
        if (length < 0 || length >= (int)sizeof(credentials)) return -1;
        base64_encode(credentials, encoded, sizeof(encoded));
        length = snprintf(auth, sizeof(auth), "Proxy-Authorization: Basic %s\r\n", encoded);
        if (length < 0 || length >= (int)sizeof(auth)) return -1;
    }
    length = snprintf(request, sizeof(request),
        "CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\n%sProxy-Connection: keep-alive\r\n\r\n",
        host, port, host, port, auth);
    if (length < 0 || length >= (int)sizeof(request)) return -1;

    DWORD old_recv = 0, old_send = 0, budget = HTTP_CONNECT_TIMEOUT_MS;
    int option_size = sizeof(DWORD);
    if (getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&old_recv, &option_size)) return -1;
    option_size = sizeof(DWORD);
    if (getsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char *)&old_send, &option_size)) return -1;
    if (old_recv && old_recv < budget) budget = old_recv;
    if (old_send && old_send < budget) budget = old_send;
    ULONGLONG deadline = GetTickCount64() + budget;
    int result = -1, sent = 0, used = 0, header_end = 0;
    while (sent < length) {
        if (!http_remaining_timeout(s, SO_SNDTIMEO, deadline)) goto done;
        int n = send(s, request + sent, length - sent, 0);
        if (n <= 0) goto done;
        sent += n;
    }
    while (!header_end || used < header_end) {
        if (used == sizeof(response)) goto done;
        if (!http_remaining_timeout(s, SO_RCVTIMEO, deadline)) goto done;
        // Peek first: bytes after CRLFCRLF belong to the tunnel, not its headers.
        int n = recv(s, response + used, (int)sizeof(response) - used, MSG_PEEK);
        if (n <= 0) goto done;
        for (int i = used > 3 ? used - 3 : 0; i + 3 < used + n; ++i) {
            if (!memcmp(response + i, "\r\n\r\n", 4)) { header_end = i + 4; break; }
        }
        int consume = header_end ? header_end - used : n;
        if (!http_remaining_timeout(s, SO_RCVTIMEO, deadline)) goto done;
        n = recv(s, response + used, consume, 0);
        if (n <= 0) goto done;
        used += n;
    }
    // Exact three-digit HTTP/1.x status; reject partial or malformed status lines.
    if (used < 16 || memcmp(response, "HTTP/1.", 7) ||
        (response[7] != '0' && response[7] != '1') || response[8] != ' ' ||
        response[9] != '2' || response[10] < '0' || response[10] > '9' ||
        response[11] < '0' || response[11] > '9' ||
        (response[12] != ' ' && response[12] != '\r')) goto done;
    result = 0; // Any 2xx CONNECT response establishes the tunnel.
done:
    {
        int error = WSAGetLastError();
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&old_recv, sizeof(old_recv));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char *)&old_send, sizeof(old_send));
        WSASetLastError(error);
    }
    if (result) log_message("HTTP: CONNECT handshake failed or response headers incomplete");
    return result;
}

int http_connect_domain(SOCKET s, const char *domain, UINT16 port, const PROXY_CONFIG *cfg)
{
    if (!domain || !pb_valid_hostname(domain)) return -1;
    return http_connect_request(s, domain, port, cfg);
}

int http_connect_v6(SOCKET s, const UINT8 dest_ip6[16], UINT16 dest_port, const PROXY_CONFIG *cfg)
{
    char domain[256], address[64], host[68];
    if (cfg && cfg->send_domain_to_proxy && dns_cache_lookup_v6(dest_ip6, domain, sizeof(domain)))
        return http_connect_request(s, domain, dest_port, cfg);
    if (!inet_ntop(AF_INET6, dest_ip6, address, sizeof(address))) return -1;
    snprintf(host, sizeof(host), "[%s]", address);
    return http_connect_request(s, host, dest_port, cfg);
}

int http_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port, const PROXY_CONFIG *cfg)
{
    char domain[256], address[32];
    if (cfg && cfg->send_domain_to_proxy && dns_cache_lookup(dest_ip, domain, sizeof(domain)))
        return http_connect_request(s, domain, dest_port, cfg);
    format_ip_address(dest_ip, address, sizeof(address));
    return http_connect_request(s, address, dest_port, cfg);
}
