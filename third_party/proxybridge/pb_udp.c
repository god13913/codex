// Scoped UDP over SOCKS5. Each application tuple owns its association and receive
// socket; replies can never be assigned to the most recently active other client.
// Included by pb_relay.c so existing native build entry points compile this module.
#define PB_UDP_MAX_FLOWS 128
#define PB_UDP_QUEUE_LIMIT 32
#define PB_UDP_IDLE_MS 60000
#define PB_UDP_MAX_DATA 65485

typedef struct PB_UDP_DATA {
    struct PB_UDP_DATA *next;
    UINT length;
    BYTE data[1];
} PB_UDP_DATA;

typedef struct PB_UDP_FLOW {
    struct PB_UDP_FLOW *next;
    BOOL ipv6;
    DWORD pid;
    UINT32 config_id;
    BYTE source[16], destination[16];
    UINT16 source_port, destination_port; // network byte order
    WINDIVERT_ADDRESS address;
    PROXY_CONFIG config;
    PB_DNS_TRACKER *dns;
    SRWLOCK queue_lock;
    PB_UDP_DATA *head, *tail;
    UINT queued;
    HANDLE thread;
    SOCKET control; // Published under pb_udp_lock so shutdown can cancel handshake I/O.
    volatile LONG stop, done;
} PB_UDP_FLOW;

static SRWLOCK pb_udp_lock = SRWLOCK_INIT;
static PB_UDP_FLOW *pb_udp_flows;
static UINT pb_udp_count;

#ifdef PB_TRANSPORT_FIXED
BOOL (*pb_udp_test_sink)(const void *, UINT, const WINDIVERT_ADDRESS *);
#endif

static BOOL pb_udp_inject(PB_UDP_FLOW *flow, const BYTE *data, UINT size)
{
    UINT header_size = flow->ipv6 ? sizeof(WINDIVERT_IPV6HDR) : sizeof(WINDIVERT_IPHDR);
    UINT length = header_size + sizeof(WINDIVERT_UDPHDR) + size;
    BYTE *packet = (BYTE *)calloc(1, length);
    if (packet == NULL) return FALSE;
    if (flow->ipv6) {
        PWINDIVERT_IPV6HDR ip = (PWINDIVERT_IPV6HDR)packet;
        ip->Version = 6;
        ip->Length = htons((UINT16)(sizeof(WINDIVERT_UDPHDR) + size));
        ip->NextHdr = IPPROTO_UDP;
        ip->HopLimit = 64;
        memcpy(ip->SrcAddr, flow->destination, 16);
        memcpy(ip->DstAddr, flow->source, 16);
    } else {
        PWINDIVERT_IPHDR ip = (PWINDIVERT_IPHDR)packet;
        ip->Version = 4;
        ip->HdrLength = 5;
        ip->Length = htons((UINT16)length);
        ip->TTL = 64;
        ip->Protocol = IPPROTO_UDP;
        memcpy(&ip->SrcAddr, flow->destination, 4);
        memcpy(&ip->DstAddr, flow->source, 4);
    }
    PWINDIVERT_UDPHDR udp = (PWINDIVERT_UDPHDR)(packet + header_size);
    udp->SrcPort = flow->destination_port;
    udp->DstPort = flow->source_port;
    udp->Length = htons((UINT16)(sizeof(*udp) + size));
    if (size != 0) memcpy(udp + 1, data, size);
    WINDIVERT_ADDRESS address = flow->address;
    address.Outbound = FALSE;
    WinDivertHelperCalcChecksums(packet, length, &address, 0);
    BOOL result;
#ifdef PB_TRANSPORT_FIXED
    if (pb_udp_test_sink != NULL) result = pb_udp_test_sink(packet, length, &address);
    else
#endif
    result = WinDivertSend(windivert_handle, packet, length, NULL, &address);
    free(packet);
    return result;
}

static PB_UDP_DATA *pb_udp_take(PB_UDP_FLOW *flow)
{
    AcquireSRWLockExclusive(&flow->queue_lock);
    PB_UDP_DATA *item = flow->head;
    if (item != NULL) {
        flow->head = item->next;
        if (flow->head == NULL) flow->tail = NULL;
        --flow->queued;
    }
    ReleaseSRWLockExclusive(&flow->queue_lock);
    return item;
}

static DWORD WINAPI pb_udp_worker(LPVOID parameter)
{
    PB_UDP_FLOW *flow = (PB_UDP_FLOW *)parameter;
    SOCKET control = INVALID_SOCKET, transport = INVALID_SOCKET;
    BYTE *buffer = (BYTE *)malloc(MAXBUF);
    if (buffer == NULL) goto finished;
    if (!pb_wait_upstream()) goto finished;
    control = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (control == INVALID_SOCKET) goto finished;
    AcquireSRWLockExclusive(&pb_udp_lock);
    flow->control = control;
    BOOL cancelled = InterlockedCompareExchange(&flow->stop, 0, 0) != 0;
    ReleaseSRWLockExclusive(&pb_udp_lock);
    if (cancelled) goto finished;
    configure_tcp_socket(control, 262144, 1500);
    struct sockaddr_in endpoint = {0}, relay = {0};
    endpoint.sin_family = AF_INET;
    endpoint.sin_addr.s_addr = flow->config.resolved_ip;
    endpoint.sin_port = htons(flow->config.port);
    if (endpoint.sin_addr.s_addr == 0 ||
        connect_with_timeout(control, (struct sockaddr *)&endpoint, sizeof(endpoint), 1500) == SOCKET_ERROR ||
        socks5_udp_associate_with_config(control, &relay, &flow->config) != 0) goto finished;
    // This module only trusts the explicitly configured local proxy's UDP relay.
    if (relay.sin_addr.s_addr == INADDR_ANY) relay.sin_addr.s_addr = endpoint.sin_addr.s_addr;
    if (relay.sin_addr.s_addr != endpoint.sin_addr.s_addr || relay.sin_port == 0) goto finished;
    transport = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (transport == INVALID_SOCKET) goto finished;
    configure_udp_socket(transport, 262144, 500);
    if (connect(transport, (struct sockaddr *)&relay, sizeof(relay)) == SOCKET_ERROR) goto finished;
    ULONGLONG activity = GetTickCount64();
    while (running && !InterlockedCompareExchange(&flow->stop, 0, 0)) {
        PB_UDP_DATA *item;
        UINT batch = 0;
        while (batch++ < PB_UDP_QUEUE_LIMIT && (item = pb_udp_take(flow)) != NULL) {
            UINT address_size = flow->ipv6 ? 16 : 4;
            UINT prefix = 4 + address_size + 2;
            memset(buffer, 0, 3);
            buffer[3] = flow->ipv6 ? SOCKS5_ATYP_IPV6 : SOCKS5_ATYP_IPV4;
            memcpy(buffer + 4, flow->destination, address_size);
            memcpy(buffer + 4 + address_size, &flow->destination_port, 2);
            memcpy(buffer + prefix, item->data, item->length);
            pb_dns_observe(flow->dns, FALSE, item->data, item->length);
            int sent = send(transport, (const char *)buffer, prefix + item->length, 0);
            free(item);
            if (sent == SOCKET_ERROR) goto finished;
            activity = GetTickCount64();
        }
        fd_set readable;
        FD_ZERO(&readable); FD_SET(control, &readable); FD_SET(transport, &readable);
        struct timeval wait = {0, 100000};
        int ready = select(0, &readable, NULL, NULL, &wait);
        if (ready == SOCKET_ERROR || FD_ISSET(control, &readable)) goto finished;
        if (ready > 0 && FD_ISSET(transport, &readable)) {
            int received = recv(transport, (char *)buffer, MAXBUF, 0);
            if (received == SOCKET_ERROR) goto finished;
            UINT address_size = flow->ipv6 ? 16 : 4, prefix = address_size + 6;
            if (received < (int)prefix || buffer[0] != 0 || buffer[1] != 0 || buffer[2] != 0 ||
                buffer[3] != (flow->ipv6 ? SOCKS5_ATYP_IPV6 : SOCKS5_ATYP_IPV4) ||
                memcmp(buffer + 4, flow->destination, address_size) ||
                memcmp(buffer + 4 + address_size, &flow->destination_port, 2)) continue;
            pb_dns_observe(flow->dns, TRUE, buffer + prefix, received - prefix);
            pb_udp_inject(flow, buffer + prefix, received - prefix);
            activity = GetTickCount64();
        }
        if (GetTickCount64() - activity > PB_UDP_IDLE_MS) break;
    }
finished:
    if (transport != INVALID_SOCKET) closesocket(transport);
    free(buffer);
    // Queue producers hold pb_udp_lock; mark done and drain under the same lock.
    AcquireSRWLockExclusive(&pb_udp_lock);
    if (control != INVALID_SOCKET) closesocket(control);
    flow->control = INVALID_SOCKET;
    InterlockedExchange(&flow->done, 1);
    PB_UDP_DATA *pending;
    while ((pending = pb_udp_take(flow)) != NULL) free(pending);
    SecureZeroMemory(&flow->config, sizeof(flow->config));
    ReleaseSRWLockExclusive(&pb_udp_lock);
    return 0;
}

static void pb_udp_reap(void)
{
    PB_UDP_FLOW **cursor = &pb_udp_flows;
    while (*cursor != NULL) {
        PB_UDP_FLOW *flow = *cursor;
        if (flow->done && WaitForSingleObject(flow->thread, 0) == WAIT_OBJECT_0) {
            *cursor = flow->next;
            CloseHandle(flow->thread);
            pb_dns_tracker_free(flow->dns);
            free(flow);
            --pb_udp_count;
        } else cursor = &flow->next;
    }
}

// Called only for a positively identified, proxy-matched application datagram.
// Failure always drops that datagram; it must never fall through to direct send.
BOOL pb_forward_udp(const void *packet, UINT packet_len, const WINDIVERT_ADDRESS *address,
                    UINT32 config_id, DWORD pid)
{
    PWINDIVERT_IPHDR ip = NULL;
    PWINDIVERT_IPV6HDR ip6 = NULL;
    PWINDIVERT_UDPHDR udp = NULL;
    void *payload = NULL;
    UINT payload_len = 0;
    if (!WinDivertHelperParsePacket(packet, packet_len, &ip, &ip6, NULL, NULL, NULL,
        NULL, &udp, &payload, &payload_len, NULL, NULL) || udp == NULL ||
        (ip == NULL && ip6 == NULL) || payload_len > PB_UDP_MAX_DATA ||
        ntohs(udp->Length) != payload_len + sizeof(*udp)) return FALSE;
    PROXY_CONFIG *config = find_proxy_config(config_id);
    if (config == NULL || config->type != PROXY_TYPE_SOCKS5) return FALSE;
    // The dedicated listener is local. Never turn a malformed configuration into a
    // direct UDP tunnel to an arbitrary relay supplied by a remote SOCKS server.
    if ((ntohl(config->resolved_ip) >> 24) != 127) return FALSE;
    BYTE source[16] = {0}, destination[16] = {0};
    UINT address_size = ip6 != NULL ? 16 : 4;
    memcpy(source, ip6 != NULL ? (const void *)ip6->SrcAddr : (const void *)&ip->SrcAddr, address_size);
    memcpy(destination, ip6 != NULL ? (const void *)ip6->DstAddr : (const void *)&ip->DstAddr, address_size);
    AcquireSRWLockExclusive(&pb_udp_lock);
    pb_udp_reap();
    PB_UDP_FLOW *flow;
    for (flow = pb_udp_flows; flow != NULL; flow = flow->next)
        if (!flow->done && flow->ipv6 == (ip6 != NULL) && flow->pid == pid && flow->config_id == config_id &&
            flow->source_port == udp->SrcPort && flow->destination_port == udp->DstPort &&
            !memcmp(flow->source, source, 16) && !memcmp(flow->destination, destination, 16)) break;
    BOOL created = FALSE, accepted = FALSE;
    if (flow == NULL && pb_udp_count < PB_UDP_MAX_FLOWS) {
        flow = (PB_UDP_FLOW *)calloc(1, sizeof(*flow));
        if (flow != NULL) {
            flow->ipv6 = ip6 != NULL; flow->pid = pid; flow->config_id = config_id;
            flow->source_port = udp->SrcPort; flow->destination_port = udp->DstPort;
            memcpy(flow->source, source, 16); memcpy(flow->destination, destination, 16);
            flow->address = *address; flow->config = *config;
            flow->dns = ntohs(udp->DstPort) == 53 ? pb_dns_tracker_new() : NULL;
            flow->control = INVALID_SOCKET;
            InitializeSRWLock(&flow->queue_lock);
            created = TRUE;
        }
    }
    if (flow != NULL) {
        AcquireSRWLockExclusive(&flow->queue_lock);
        PB_UDP_DATA *item = flow->queued < PB_UDP_QUEUE_LIMIT ?
            (PB_UDP_DATA *)malloc(sizeof(*item) + payload_len) : NULL;
        if (item != NULL) {
            item->next = NULL; item->length = payload_len;
            if (payload_len != 0) memcpy(item->data, payload, payload_len);
            if (flow->tail != NULL) flow->tail->next = item; else flow->head = item;
            flow->tail = item; ++flow->queued; accepted = TRUE;
        }
        ReleaseSRWLockExclusive(&flow->queue_lock);
        if (created) {
            flow->thread = accepted ? CreateThread(NULL, 65536, pb_udp_worker, flow,
                STACK_SIZE_PARAM_IS_A_RESERVATION, NULL) : NULL;
            if (flow->thread == NULL) {
                PB_UDP_DATA *item;
                while ((item = pb_udp_take(flow)) != NULL) free(item);
                SecureZeroMemory(&flow->config, sizeof(flow->config));
                pb_dns_tracker_free(flow->dns);
                free(flow); accepted = FALSE;
            } else {
                flow->next = pb_udp_flows; pb_udp_flows = flow; ++pb_udp_count;
            }
        }
    }
    ReleaseSRWLockExclusive(&pb_udp_lock);
    return accepted;
}

BOOL pb_udp_stop(void)
{
    AcquireSRWLockExclusive(&pb_udp_lock);
    for (PB_UDP_FLOW *flow = pb_udp_flows; flow != NULL; flow = flow->next) {
        InterlockedExchange(&flow->stop, 1);
        if (flow->control != INVALID_SOCKET) shutdown(flow->control, SD_BOTH);
    }
    ReleaseSRWLockExclusive(&pb_udp_lock);
    ULONGLONG deadline = GetTickCount64() + 10000;
    for (;;) {
        AcquireSRWLockExclusive(&pb_udp_lock);
        pb_udp_reap();
        BOOL empty = pb_udp_flows == NULL;
        ReleaseSRWLockExclusive(&pb_udp_lock);
        if (empty) return TRUE;
        if (GetTickCount64() >= deadline) return FALSE;
        Sleep(10);
    }
}
