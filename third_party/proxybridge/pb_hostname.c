// Included by pb_relay.c. Inspect a bounded prefix without consuming application bytes.
#define PB_HELLO_LIMIT 65536
#define PB_HELLO_BUDGET_MS 1000

BOOL pb_valid_hostname(const char *host)
{
    size_t length = strnlen_s(host, 256), label = 0;
    if (!length || length > 253) return FALSE;
    struct in_addr v4; struct in6_addr v6;
    if (inet_pton(AF_INET, host, &v4) == 1 || inet_pton(AF_INET6, host, &v6) == 1) return FALSE;
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)host[i];
        if (c == '.') {
            if (!label || host[i - 1] == '-') return FALSE;
            label = 0;
        } else {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '-') || (!label && c == '-') || ++label > 63) return FALSE;
        }
    }
    return label > 0 && host[length - 1] != '-';
}

static UINT pb_u16(const BYTE *p) { return ((UINT)p[0] << 8) | p[1]; }

// 1: hostname, 0: incomplete, -1: not an unambiguous DNS hostname.
static int pb_client_hello(const BYTE *data, UINT size, char host[256])
{
    if (size < 4) return 0;
    UINT length = ((UINT)data[1] << 16) | ((UINT)data[2] << 8) | data[3];
    if (data[0] != 1 || length > PB_HELLO_LIMIT - 4) return -1;
    if (size < length + 4) return 0;
    UINT end = length + 4, pos = 4 + 2 + 32;
    if (pos >= end) return -1;
    UINT count = data[pos++];
    if (count > end - pos) return -1;
    pos += count;
    if (end - pos < 2) return -1;
    count = pb_u16(data + pos); pos += 2;
    if (!count || (count & 1) || count > end - pos) return -1;
    pos += count;
    if (pos >= end) return -1;
    count = data[pos++];
    if (!count || count > end - pos) return -1;
    pos += count;
    if (end - pos < 2 || pb_u16(data + pos) != end - pos - 2) return -1;
    pos += 2;
    BOOL found = FALSE;
    while (pos < end) {
        if (end - pos < 4) return -1;
        UINT type = pb_u16(data + pos), bytes = pb_u16(data + pos + 2); pos += 4;
        if (bytes > end - pos) return -1;
        // Use the visible TLS routing name. An ECH extension may be GREASE;
        // its presence alone does not mean SNI is unusable. Never decrypt TLS.
        if (type == 0) {
            if (found || bytes < 5 || pb_u16(data + pos) != bytes - 2) return -1;
            UINT cursor = pos + 2, stop = pos + bytes;
            while (cursor < stop) {
                if (stop - cursor < 3) return -1;
                UINT name_type = data[cursor], name_size = pb_u16(data + cursor + 1); cursor += 3;
                if (name_size > stop - cursor) return -1;
                if (name_type == 0) {
                    if (found || !name_size || name_size > 253 || memchr(data + cursor, 0, name_size)) return -1;
                    memcpy(host, data + cursor, name_size); host[name_size] = 0;
                    if (!pb_valid_hostname(host)) return -1;
                    found = TRUE;
                }
                cursor += name_size;
            }
        }
        pos += bytes;
    }
    return found ? 1 : -1;
}

int pb_tls_hostname(const BYTE *data, UINT length, char host[256])
{
    BYTE *hello = (BYTE *)malloc(PB_HELLO_LIMIT);
    if (hello == NULL) return -1;
    UINT pos = 0, used = 0;
    int result = 0;
    while (pos < length) {
        if (length - pos < 5) break;
        UINT count = pb_u16(data + pos + 3);
        if (data[pos] != 22 || data[pos + 1] != 3 || !count || count > 18432 || count > PB_HELLO_LIMIT - used) {
            result = -1; break;
        }
        if (count > length - pos - 5) break;
        memcpy(hello + used, data + pos + 5, count); used += count; pos += count + 5;
        result = pb_client_hello(hello, used, host);
        if (result != 0) break;
    }
    free(hello);
    return result;
}

int pb_http_hostname(const BYTE *data, UINT length, char host[256])
{
    if (length > 16384) length = 16384;
    UINT end = 0;
    for (UINT i = 0; i + 3 < length; ++i)
        if (!memcmp(data + i, "\r\n\r\n", 4)) { end = i + 2; break; }
    if (!end) return 0;
    if (memchr(data, 0, end)) return -1;
    BOOL found = FALSE;
    for (UINT pos = 0; pos < end;) {
        UINT stop = pos;
        while (stop + 1 < end + 2 && memcmp(data + stop, "\r\n", 2)) ++stop;
        if (stop + 1 >= end + 2) return -1;
        if (stop - pos >= 5 && !_strnicmp((const char *)data + pos, "Host:", 5)) {
            if (found) return -1;
            UINT first = pos + 5, last = stop;
            while (first < last && (data[first] == ' ' || data[first] == '\t')) ++first;
            while (last > first && (data[last - 1] == ' ' || data[last - 1] == '\t')) --last;
            UINT colon = first;
            while (colon < last && data[colon] != ':') ++colon;
            if (colon < last) {
                if (colon + 1 == last) return -1;
                UINT port = 0;
                for (UINT i = colon + 1; i < last; ++i) {
                    if (data[i] < '0' || data[i] > '9' || port > 6553) return -1;
                    port = port * 10 + data[i] - '0';
                }
                if (!port || port > 65535) return -1;
            }
            UINT size = colon - first;
            if (!size || size > 253) return -1;
            memcpy(host, data + first, size); host[size] = 0;
            if (!pb_valid_hostname(host)) return -1;
            found = TRUE;
        }
        pos = stop + 2;
    }
    return found ? 1 : -1;
}

BOOL pb_peek_hostname(SOCKET client, UINT16 port, char host[256])
{
    if (port != 80 && port != 443) return FALSE;
    BYTE *buffer = (BYTE *)malloc(PB_HELLO_LIMIT);
    if (!buffer) return FALSE;
    DWORD original = 0; int size = sizeof(original);
    if (getsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char *)&original, &size)) { free(buffer); return FALSE; }
    ULONGLONG deadline = GetTickCount64() + PB_HELLO_BUDGET_MS;
    int previous = -1; BOOL found = FALSE;
    while (running) {
        ULONGLONG now = GetTickCount64();
        if (now >= deadline) break;
        DWORD timeout = (DWORD)(deadline - now);
        if (setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout))) break;
        int count = recv(client, (char *)buffer, PB_HELLO_LIMIT, MSG_PEEK);
        if (count <= 0) break;
        if (count != previous) {
            int result = port == 443 ? pb_tls_hostname(buffer, count, host) : pb_http_hostname(buffer, count, host);
            if (result != 0) { found = result == 1; break; }
            previous = count;
        }
        Sleep(2); // MSG_PEEK does not wait for more bytes when a partial prefix is buffered.
    }
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char *)&original, sizeof(original));
    free(buffer);
    return found;
}
