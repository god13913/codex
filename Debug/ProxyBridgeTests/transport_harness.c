// Standalone loopback tests. Never calls ProxyBridge_Start or opens WinDivert.
#include "pb_internal.h"
#include <fcntl.h>
#include <io.h>

static SOCKET listener(UINT16 *port)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) || listen(s, 2)) exit(90);
    int n = sizeof(a);
    getsockname(s, (struct sockaddr *)&a, &n);
    *port = ntohs(a.sin_port);
    return s;
}

static DWORD WINAPI cancel_relay(LPVOID arg)
{
    Sleep((DWORD)(ULONG_PTR)arg);
    running = FALSE;
    return 0;
}

#ifdef PB_TRANSPORT_FIXED
static BOOL filter_fixture(const char *filter, BOOL ipv6, BOOL tcp, BOOL impostor,
                           BOOL outbound, BOOL loopback, UINT16 source, UINT16 destination)
{
    BYTE packet[80] = {0};
    UINT header = ipv6 ? sizeof(WINDIVERT_IPV6HDR) : sizeof(WINDIVERT_IPHDR);
    UINT size = header + (tcp ? sizeof(WINDIVERT_TCPHDR) : sizeof(WINDIVERT_UDPHDR)) + 1;
    if (ipv6) {
        PWINDIVERT_IPV6HDR ip = (PWINDIVERT_IPV6HDR)packet;
        ip->Version = 6; ip->NextHdr = tcp ? IPPROTO_TCP : IPPROTO_UDP;
        ip->Length = htons((UINT16)(size - header)); ip->HopLimit = 64;
        ip->SrcAddr[3] = 1; ip->DstAddr[3] = 2;
    } else {
        PWINDIVERT_IPHDR ip = (PWINDIVERT_IPHDR)packet;
        ip->Version = 4; ip->HdrLength = 5; ip->Protocol = tcp ? IPPROTO_TCP : IPPROTO_UDP;
        ip->Length = htons((UINT16)size); ip->TTL = 64;
        ip->SrcAddr = inet_addr("192.0.2.1"); ip->DstAddr = inet_addr("198.51.100.2");
    }
    if (tcp) {
        PWINDIVERT_TCPHDR h = (PWINDIVERT_TCPHDR)(packet + header);
        h->SrcPort = htons(source); h->DstPort = htons(destination); h->HdrLength = 5;
    } else {
        PWINDIVERT_UDPHDR h = (PWINDIVERT_UDPHDR)(packet + header);
        h->SrcPort = htons(source); h->DstPort = htons(destination);
        h->Length = htons(sizeof(*h) + 1);
    }
    WINDIVERT_ADDRESS address = {0};
    address.IPv6 = ipv6; address.Outbound = outbound;
    address.Impostor = impostor; address.Loopback = loopback;
    return WinDivertHelperEvalFilter(filter, packet, size, &address);
}

static DWORD WINAPI release_upstream(LPVOID arg)
{
    Sleep(200); ProxyBridge_SetUpstreamReady(TRUE); return 0;
}
extern BOOL (*pb_udp_test_sink)(const void *, UINT, const WINDIVERT_ADDRESS *);
static SRWLOCK output_lock = SRWLOCK_INIT;
static volatile LONG udp_replies;

static BOOL udp_sink(const void *packet, UINT length, const WINDIVERT_ADDRESS *address)
{
    PWINDIVERT_UDPHDR udp = NULL;
    void *payload = NULL; UINT payload_length = 0;
    WinDivertHelperParsePacket(packet, length, NULL, NULL, NULL, NULL, NULL, NULL,
        &udp, &payload, &payload_length, NULL, NULL);
    if (udp == NULL || address->Outbound) return FALSE;
    AcquireSRWLockExclusive(&output_lock);
    printf("{\"udp_reply_port\":%u,\"data\":\"", ntohs(udp->DstPort));
    for (UINT i = 0; i < payload_length; ++i) printf("%02x", ((BYTE *)payload)[i]);
    puts("\"}"); fflush(stdout);
    ReleaseSRWLockExclusive(&output_lock);
    InterlockedIncrement(&udp_replies);
    return TRUE;
}

static BOOL udp_fixture_data(UINT32 config, BOOL ipv6, UINT16 source_port, BOOL other_peer,
                             const BYTE *data, UINT size, const char *destination)
{
    UINT header_length = ipv6 ? sizeof(WINDIVERT_IPV6HDR) : sizeof(WINDIVERT_IPHDR);
    UINT length = header_length + sizeof(WINDIVERT_UDPHDR) + size;
    if (size > 65485) return FALSE;
    BYTE *packet = calloc(1, length);
    if (packet == NULL) return FALSE;
    if (ipv6) {
        PWINDIVERT_IPV6HDR ip = (PWINDIVERT_IPV6HDR)packet;
        ip->Version = 6; ip->NextHdr = IPPROTO_UDP; ip->HopLimit = 64;
        ip->Length = htons((UINT16)(length - header_length));
        inet_pton(AF_INET6, "2001:db8::1", ip->SrcAddr);
        inet_pton(AF_INET6, "2001:db8::5", ip->DstAddr);
    } else {
        PWINDIVERT_IPHDR ip = (PWINDIVERT_IPHDR)packet;
        ip->Version = 4; ip->HdrLength = 5; ip->Protocol = IPPROTO_UDP; ip->TTL = 64;
        ip->Length = htons((UINT16)length);
        ip->SrcAddr = inet_addr("192.0.2.1");
        ip->DstAddr = inet_addr(destination != NULL ? destination :
            (other_peer ? "198.51.100.3" : "198.51.100.2"));
    }
    PWINDIVERT_UDPHDR udp = (PWINDIVERT_UDPHDR)(packet + header_length);
    udp->SrcPort = htons(source_port); udp->DstPort = htons(other_peer ? 3478 : 443);
    udp->Length = htons((UINT16)(sizeof(*udp) + size));
    memcpy(udp + 1, data, size);
    WINDIVERT_ADDRESS address = {0}; address.Outbound = TRUE; address.IPv6 = ipv6;
    WinDivertHelperCalcChecksums(packet, length, &address, 0);
    BOOL accepted = pb_forward_udp(packet, length, &address, config, 1234);
    free(packet);
    return accepted;
}

static BOOL udp_fixture(UINT32 config, BOOL ipv6, UINT16 source_port, BOOL other_peer, const char *data)
{
    return udp_fixture_data(config, ipv6, source_port, other_peer,
        (const BYTE *)data, (UINT)strlen(data), NULL);
}
#endif

int main(int argc, char **argv)
{
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#ifdef PB_TRANSPORT_FIXED
    if (argc > 1 && !strcmp(argv[1], "capture-filter")) {
        // Evaluate the exact production filter with WinDivert's real compiler,
        // without opening a driver handle or sending any network traffic.
        char filter[FILTER_BUFFER_SIZE], object[8192];
        pb_build_packet_filter(filter, 45555);
        if (!WinDivertHelperCompileFilter(filter, WINDIVERT_LAYER_NETWORK,
            object, sizeof(object), NULL, NULL)) return 99;
        int checked = 0, failures = 0;
        UINT16 ports[] = {53, 80, 443, 3478, 35234, 45555, 67, 68, 546, 547, 22};
        for (int v6 = 0; v6 <= 1; ++v6)
        for (int tcp = 0; tcp <= 1; ++tcp)
        for (int impostor = 0; impostor <= 1; ++impostor)
        for (int outbound = 0; outbound <= 1; ++outbound)
        for (int loopback = 0; loopback <= 1; ++loopback)
        for (int relay_source = 0; relay_source <= 1; ++relay_source)
        for (unsigned p = 0; p < sizeof(ports) / sizeof(ports[0]); ++p) {
            UINT16 destination = ports[p], source = relay_source ? 45555 : 45000;
            BOOL expected = !loopback && (tcp ? (!impostor &&
                ((outbound && (destination == 53 || destination == 80 || destination == 443)) ||
                 destination == 45555 || source == 45555)) :
                (outbound && destination != 67 && destination != 68 && destination != 546 && destination != 547));
            BOOL actual = filter_fixture(object, v6, tcp, impostor, outbound, loopback, source, destination);
            ++checked;
            if (actual != expected) ++failures;
        }
        BOOL old_rejected = !filter_fixture("not impostor and not loopback and outbound and udp",
            FALSE, FALSE, TRUE, TRUE, FALSE, 45000, 443);
        if (!old_rejected) ++failures;
        printf("{\"checks\":%d,\"failures\":%d,\"old_rejects_injected_quic\":%s}\n",
            checked, failures, old_rejected ? "true" : "false");
        return failures != 0;
    }
    if (argc > 1 && !strcmp(argv[1], "udp-owner")) {
        DWORD self = GetCurrentProcessId();
        SOCKET socket4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        struct sockaddr_in a4 = {0}; a4.sin_family = AF_INET; a4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (socket4 == INVALID_SOCKET || bind(socket4, (struct sockaddr *)&a4, sizeof(a4))) return 96;
        int size = sizeof(a4); getsockname(socket4, (struct sockaddr *)&a4, &size);
        BOOL ipv4 = get_process_id_from_udp_connection(a4.sin_addr.s_addr, ntohs(a4.sin_port)) == self;
        SOCKET socket6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        DWORD only6 = 0; setsockopt(socket6, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&only6, sizeof(only6));
        struct sockaddr_in6 a6 = {0}; a6.sin6_family = AF_INET6;
        if (socket6 == INVALID_SOCKET || bind(socket6, (struct sockaddr *)&a6, sizeof(a6))) return 97;
        size = sizeof(a6); getsockname(socket6, (struct sockaddr *)&a6, &size);
        UINT16 port = ntohs(a6.sin6_port);
        BOOL dual_bound = get_process_id_from_udp_connection(htonl(INADDR_LOOPBACK), port) == self;
        BOOL ipv6 = get_process_id_from_udp_connection_v6((BYTE *)&a6.sin6_addr, port) == self;
        struct sockaddr_in6 remote = {0}; remote.sin6_family = AF_INET6; remote.sin6_port = htons(9);
        inet_pton(AF_INET6, "::ffff:127.0.0.1", &remote.sin6_addr);
        if (connect(socket6, (struct sockaddr *)&remote, sizeof(remote))) return 98;
        size = sizeof(a6); getsockname(socket6, (struct sockaddr *)&a6, &size);
        BOOL dual_connected = get_process_id_from_udp_connection(htonl(INADDR_LOOPBACK), port) == self;
        closesocket(socket4); closesocket(socket6);
        printf("{\"ipv4\":%s,\"ipv6\":%s,\"dual_bound_ipv4\":%s,\"dual_connected_ipv4\":%s}\n",
            ipv4 ? "true" : "false", ipv6 ? "true" : "false", dual_bound ? "true" : "false", dual_connected ? "true" : "false");
        return ipv4 && ipv6 && dual_bound && dual_connected ? 0 : 1;
    }
    if (argc > 3 && !strcmp(argv[1], "udp-pipe")) {
        // Diagnostic stdin/stdout stays inside the parent; no packet bytes or
        // credentials are persisted. Never starts WinDivert or changes rules.
        char *user = getenv("PB_TEST_PROXY_USER"), *password = getenv("PB_TEST_PROXY_PASSWORD");
        struct in_addr destination;
        if (user == NULL || password == NULL || inet_pton(AF_INET, argv[3], &destination) != 1) return 93;
        running = TRUE; pb_udp_test_sink = udp_sink;
        UINT32 config = ProxyBridge_AddProxyConfig(PROXY_TYPE_SOCKS5, "127.0.0.1",
            (UINT16)atoi(argv[2]), user, password, TRUE);
        char *line = malloc(131080); BYTE *data = malloc(65536);
        if (!config || !line || !data) return 94;
        while (fgets(line, 131080, stdin)) {
            line[strcspn(line, "\r\n")] = 0;
            size_t chars = strlen(line);
            if (chars % 2 != 0 || chars > 65485 * 2) break;
            BOOL valid = TRUE;
            for (size_t i = 0; i < chars; ++i)
                if (!((line[i] >= '0' && line[i] <= '9') || (line[i] >= 'a' && line[i] <= 'f'))) valid = FALSE;
            if (!valid) break;
            for (size_t i = 0; i < chars / 2; ++i) {
                unsigned byte = 0; sscanf_s(line + 2 * i, "%2x", &byte); data[i] = (BYTE)byte;
            }
            if (!udp_fixture_data(config, FALSE, 45000, FALSE, data, (UINT)(chars / 2), argv[3])) {
                puts("{\"queue_rejected\":true}"); fflush(stdout);
            }
        }
        running = FALSE;
        BOOL stopped = pb_udp_stop();
        free(line); free(data);
        return stopped ? 0 : 95;
    }
    if (argc > 1 && !strcmp(argv[1], "gate-stop")) {
        running = TRUE; ProxyBridge_SetUpstreamReady(FALSE);
        HANDLE cancel = CreateThread(NULL, 0, cancel_relay, (LPVOID)(ULONG_PTR)100, 0, NULL);
        BOOL passed = pb_wait_upstream();
        WaitForSingleObject(cancel, INFINITE); CloseHandle(cancel);
        printf("{\"allowed\":%s}\n", passed ? "true" : "false");
        return passed ? 1 : 0;
    }
    if (argc > 2 && !strcmp(argv[1], "inspect")) {
        BYTE data[65536]; char host[256] = {0};
        _setmode(_fileno(stdin), _O_BINARY);
        UINT n = (UINT)fread(data, 1, sizeof(data), stdin);
        int result = !strcmp(argv[2], "tls") ? pb_tls_hostname(data, n, host) : pb_http_hostname(data, n, host);
        printf("{\"result\":%d,\"host\":\"%s\"}\n", result, result == 1 ? host : "");
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "cache")) {
        dns_cache_init(); PB_DNS_TRACKER *tracker = pb_dns_tracker_new();
        char *line = malloc(131080); BYTE *data = malloc(65536); char host[256];
        if (!line || !data || !tracker) return 92;
        while (fgets(line, 131080, stdin)) {
            line[strcspn(line, "\r\n")] = 0;
            if (line[0] == '4' || line[0] == '6') {
                UINT8 ip6[16]; BOOL found;
                if (line[0] == '4') found = dns_cache_lookup(inet_addr(line + 1), host, sizeof(host));
                else { inet_pton(AF_INET6, line + 1, ip6); found = dns_cache_lookup_v6(ip6, host, sizeof(host)); }
                printf("{\"found\":%s,\"host\":\"%s\"}\n", found ? "true" : "false", found ? host : "");
            } else if (line[0] == 'w') Sleep((DWORD)atoi(line + 1));
            else {
                UINT size = (UINT)strlen(line + 1) / 2;
                for (UINT i = 0; i < size; ++i) { unsigned byte = 0; sscanf_s(line + 1 + i * 2, "%2x", &byte); data[i] = (BYTE)byte; }
                if (line[0] == 'q' || line[0] == 'r') pb_dns_observe(tracker, line[0] == 'r', data, size);
                else if (line[0] == 'u' || line[0] == 'd') pb_dns_stream(tracker, line[0] == 'd', data, size);
            }
        }
        pb_dns_tracker_free(tracker); free(line); free(data); return 0;
    }
    if (argc > 3 && !strcmp(argv[1], "forward")) {
        dns_cache_init(); running = TRUE;
        ProxyBridge_SetUpstreamReady(FALSE);
        UINT32 proxy = ProxyBridge_AddProxyConfig(PROXY_TYPE_HTTP, "127.0.0.1", (UINT16)atoi(argv[2]), "", "", TRUE);
        UINT16 port; SOCKET server = listener(&port);
        printf("{\"port\":%u}\n", port); fflush(stdout);
        CONNECTION_CONFIG *connection = calloc(1, sizeof(*connection));
        connection->client_socket = accept(server, NULL, NULL); closesocket(server);
        connection->orig_dest_ip = inet_addr("198.51.100.1");
        connection->orig_dest_port = (UINT16)atoi(argv[3]); connection->proxy_config_id = proxy;
        // Current SNI/Host wins over stale cache; otherwise valid DNS is a fallback.
        dns_cache_store(connection->orig_dest_ip, argc > 4 ? "cdn.platform.openai.com" : "wrong.example");
        HANDLE gate = CreateThread(NULL, 0, release_upstream, NULL, 0, NULL);
        DWORD result = connection_handler(connection);
        WaitForSingleObject(gate, INFINITE); CloseHandle(gate);
        return result;
    }
    if (argc > 2 && !strcmp(argv[1], "udp")) {
        running = TRUE;
        pb_udp_test_sink = udp_sink;
        UINT32 config = ProxyBridge_AddProxyConfig(PROXY_TYPE_SOCKS5, "127.0.0.1",
            (UINT16)atoi(argv[2]), "user", "pass", TRUE);
        BOOL accepted = udp_fixture(config, FALSE, 45000, FALSE, "one") &&
            udp_fixture(config, FALSE, 45001, FALSE, "two") &&
            udp_fixture(config, FALSE, 45000, TRUE, "three") &&
            udp_fixture(config, TRUE, 45002, FALSE, "four");
        ULONGLONG deadline = GetTickCount64() + 3500;
        while (udp_replies < 4 && GetTickCount64() < deadline) Sleep(10);
        running = FALSE;
        BOOL stopped = pb_udp_stop();
        printf("{\"accepted\":%s,\"replies\":%ld,\"stopped\":%s}\n",
            accepted ? "true" : "false", udp_replies, stopped ? "true" : "false");
        return !accepted || !stopped;
    }
#endif
    if (argc > 1 && !strcmp(argv[1], "http")) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = htons((UINT16)atoi(argv[2]));
        DWORD timeout = (DWORD)atoi(argv[4]);
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
        if (connect(s, (struct sockaddr *)&a, sizeof(a))) return 91;
        PROXY_CONFIG cfg = {0};
        if (argc > 5) {
            strcpy_s(cfg.username, sizeof(cfg.username), "user");
            strcpy_s(cfg.password, sizeof(cfg.password), "pass");
        }
        ULONGLONG start = GetTickCount64();
        UINT8 ip6[16] = {0}; ip6[15] = 1;
        int rc = atoi(argv[3]) == 6 ? http_connect_v6(s, ip6, 443, &cfg)
                                  : http_connect(s, htonl(INADDR_LOOPBACK), 443, &cfg);
        ULONGLONG elapsed = GetTickCount64() - start;
        DWORD restored = 0;
        int optlen = sizeof(restored);
        getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&restored, &optlen);
        char data[64];
        timeout = 300;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
        int n = rc == 0 ? recv(s, data, sizeof(data), 0) : 0;
        printf("{\"rc\":%d,\"ms\":%llu,\"restored_timeout\":%lu,\"tail\":\"", rc, elapsed, restored);
        for (int i = 0; i < n; ++i) printf("%02x", (unsigned char)data[i]);
        puts("\"}");
        closesocket(s);
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "relay")) {
        UINT16 p1, p2;
        SOCKET l1 = listener(&p1), l2 = listener(&p2);
        printf("{\"ports\":[%u,%u]}\n", p1, p2); fflush(stdout);
        TRANSFER_CONFIG *cfg = malloc(sizeof(*cfg));
        cfg->dns = argc > 3 ? pb_dns_tracker_new() : NULL;
        cfg->from_socket = accept(l1, NULL, NULL);
        cfg->to_socket = accept(l2, NULL, NULL);
        closesocket(l1); closesocket(l2);
        puts("{\"accepted\":true}"); fflush(stdout);
        running = TRUE;
        HANDLE cancel = NULL;
        if (argc > 2 && atoi(argv[2]))
            cancel = CreateThread(NULL, 0, cancel_relay, (LPVOID)(ULONG_PTR)atoi(argv[2]), 0, NULL);
        DWORD rc = transfer_handler(cfg);
        if (cancel) { WaitForSingleObject(cancel, INFINITE); CloseHandle(cancel); }
        printf("{\"rc\":%lu}\n", rc);
        return 0;
    }
#ifdef PB_TRANSPORT_FIXED
    if (argc > 1 && !strcmp(argv[1], "tracking")) {
        int failed = 0;
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "tracking line %d\n", __LINE__); ++failed; } } while (0)
        CHECK(ProxyBridge_GetTcpRelayPort() == 0); // No listener/driver was started.
        g_local_relay_port = 45555;
        UINT32 src = inet_addr("192.0.2.1"), dst = inet_addr("198.51.100.1");
        UINT8 src6[16] = {0}, dst6[16] = {0}; src6[15] = 1; dst6[15] = 2;
        for (int v6 = 0; v6 <= 1; ++v6) {
            UINT16 p = (UINT16)(45000 + v6), original;
            // Each captured TCP service, including DNS, must restore replies.
            // Adding DNS must not admit another service or an incorrect tuple.
            UINT16 services[] = {53, 80, 443, 22};
            for (unsigned i = 0; i < sizeof(services)/sizeof(services[0]); ++i) {
                UINT16 probe = (UINT16)(46000 + v6 * 10 + i);
                if (v6) add_connection_v6(probe, FALSE, src6, dst6, services[i], 1);
                else add_connection(probe, FALSE, src, dst, services[i], 1);
                BOOL accepted = v6
                    ? get_relay_response_v6(TRUE, src6, dst6, g_local_relay_port, probe, &original)
                    : get_relay_response_v4(TRUE, src, dst, g_local_relay_port, probe, &original);
                CHECK(accepted == (services[i] != 22));
                if (accepted) CHECK(original == services[i]);
                CHECK(!(v6 ? get_relay_response_v6(FALSE, src6, dst6, g_local_relay_port, probe, &original)
                           : get_relay_response_v4(FALSE, src, dst, g_local_relay_port, probe, &original)));
                CHECK(!(v6 ? get_relay_response_v6(TRUE, dst6, src6, g_local_relay_port, probe, &original)
                           : get_relay_response_v4(TRUE, dst, src, g_local_relay_port, probe, &original)));
                CHECK(!(v6 ? get_relay_response_v6(TRUE, src6, dst6, (UINT16)(g_local_relay_port + 1), probe, &original)
                           : get_relay_response_v4(TRUE, src, dst, (UINT16)(g_local_relay_port + 1), probe, &original)));
            }
            if (v6) add_connection_v6(p, FALSE, src6, dst6, 443, 1);
            else add_connection(p, FALSE, src, dst, 443, 1);
            remember_tcp_syn(p, v6, 100);
            note_tcp_close(p, v6, FALSE, TRUE, FALSE);
            CHECK(is_connection_tracked(p, FALSE, v6));
            CHECK(v6 ? get_relay_response_v6(TRUE, src6, dst6, g_local_relay_port, p, &original)
                     : get_relay_response_v4(TRUE, src, dst, g_local_relay_port, p, &original));
            CHECK(original == 443);
            // A retransmitted SYN keeps its mapping; a new ISN must evict it.
            prepare_tcp_syn(p, v6, v6 ? (void *)src6 : (void *)&src,
                v6 ? (void *)dst6 : (void *)&dst, 443, 100);
            CHECK(is_connection_tracked(p, FALSE, v6));
            note_tcp_close(p, v6, TRUE, TRUE, FALSE);
            CONNECTION_INFO *c = connection_hash_table[p % CONNECTION_HASH_SIZE];
            CHECK(c && c->tcp_fin_mask == 3 && c->tcp_closed_at != 0);
            c->tcp_closed_at = GetTickCount64() - CONNECTION_CLOSE_GRACE_MS - 1;
            cleanup_stale_connections();
            CHECK(!is_connection_tracked(p, FALSE, v6));
            if (v6) add_connection_v6(p, FALSE, src6, dst6, 443, 1);
            else add_connection(p, FALSE, src, dst, 443, 1);
            remember_tcp_syn(p, v6, 100);
            prepare_tcp_syn(p, v6, v6 ? (void *)src6 : (void *)&src,
                v6 ? (void *)dst6 : (void *)&dst, 443, 101);
            CHECK(!is_connection_tracked(p, FALSE, v6));
            if (v6) add_connection_v6(p, FALSE, src6, dst6, 443, 1);
            else add_connection(p, FALSE, src, dst, 443, 1);
            note_tcp_close(p, v6, FALSE, FALSE, TRUE);
            c = connection_hash_table[p % CONNECTION_HASH_SIZE];
            CHECK(c && c->tcp_reset && c->tcp_closed_at != 0);
            c->tcp_closed_at = GetTickCount64() - CONNECTION_RESET_GRACE_MS - 1;
            cleanup_stale_connections();
            CHECK(!is_connection_tracked(p, FALSE, v6));
        }
        printf("{\"failures\":%d}\n", failed);
        return failed != 0;
    }
#endif
    return 92;
}
