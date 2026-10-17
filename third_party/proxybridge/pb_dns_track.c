// Included by pb_dns.c. A tracker belongs to exactly one application flow.
#define PB_DNS_PENDING 16
#define PB_DNS_FRAME 65537
typedef struct PB_DNS_QUERY {
    UINT16 id, type;
    ULONGLONG expires;
    char name[256];
} PB_DNS_QUERY;
typedef struct PB_DNS_STREAM {
    BYTE *data;
    UINT used, needed;
    BOOL disabled;
} PB_DNS_STREAM;
struct PB_DNS_TRACKER {
    SRWLOCK lock;
    UINT next;
    PB_DNS_QUERY pending[PB_DNS_PENDING];
    PB_DNS_STREAM streams[2];
};
static UINT16 pb_dns_u16(const BYTE *p) { return ((UINT16)p[0] << 8) | p[1]; }
static UINT32 pb_dns_u32(const BYTE *p) {
    return ((UINT32)p[0] << 24) | ((UINT32)p[1] << 16) | ((UINT32)p[2] << 8) | p[3];
}
PB_DNS_TRACKER *pb_dns_tracker_new(void)
{
    PB_DNS_TRACKER *t = (PB_DNS_TRACKER *)calloc(1, sizeof(*t));
    if (t) InitializeSRWLock(&t->lock);
    return t;
}
void pb_dns_tracker_free(PB_DNS_TRACKER *t)
{
    if (!t) return;
    free(t->streams[0].data); free(t->streams[1].data); free(t);
}

static BOOL pb_dns_question(const BYTE *p, UINT n, char name[256], UINT16 *type, int *offset)
{
    if (n < 12 || n > 65535 || pb_dns_u16(p + 4) != 1) return FALSE;
    *offset = 12;
    if (!dns_parse_name(p, n, offset, name, 256) || *offset + 4 > (int)n ||
        !pb_valid_hostname(name) || pb_dns_u16(p + *offset + 2) != 1) return FALSE;
    *type = pb_dns_u16(p + *offset); *offset += 4;
    return TRUE;
}

// Validate the complete answer section before committing anything. Only owners
// reachable through the question's CNAME chain may contribute addresses.
void snoop_dns_response(const UINT8 *p, int n)
{
    char question[256]; UINT16 type; int start;
    if (!pb_dns_question(p, n, question, &type, &start) ||
        (pb_dns_u16(p + 2) & 0xFA0F) != 0x8000) return;
    UINT count = pb_dns_u16(p + 6);
    if (!count || count > 256) return;
    int offsets[256], pos = start;
    for (UINT i = 0; i < count; ++i) {
        char owner[256]; offsets[i] = pos;
        if (!dns_parse_name(p, n, &pos, owner, 256) || pos + 10 > n) return;
        UINT bytes = pb_dns_u16(p + pos + 8), rr = pb_dns_u16(p + pos);
        pos += 10;
        if (bytes > (UINT)(n - pos)) return;
        if (rr == 5) {
            int end = pos; char target[256];
            if (!dns_parse_name(p, n, &end, target, 256) || end != pos + bytes ||
                !pb_valid_hostname(target)) return;
        }
        pos += bytes;
    }
    char current[256]; strcpy_s(current, sizeof(current), question);
    UINT32 lifetime = DNS_CACHE_TTL_MS / 1000;
    // DNS CNAME chains are bounded; loops never contribute an address.
    for (UINT hop = 0; hop < 16; ++hop) {
        BOOL alias = FALSE; char next[256] = {0};
        for (UINT i = 0; i < count; ++i) {
            int offset = offsets[i]; char owner[256];
            dns_parse_name(p, n, &offset, owner, 256);
            if (_stricmp(owner, current) || pb_dns_u16(p + offset + 2) != 1 ||
                pb_dns_u16(p + offset) != 5) continue;
            char target[256]; int data = offset + 10;
            dns_parse_name(p, n, &data, target, 256);
            if (alias && _stricmp(next, target)) return;
            strcpy_s(next, sizeof(next), target); alias = TRUE;
            UINT32 ttl = pb_dns_u32(p + offset + 4);
            if (ttl < lifetime) lifetime = ttl;
        }
        if (alias) { strcpy_s(current, sizeof(current), next); continue; }
        for (UINT i = 0; i < count; ++i) {
            int offset = offsets[i]; char owner[256];
            dns_parse_name(p, n, &offset, owner, 256);
            if (_stricmp(owner, current) || pb_dns_u16(p + offset + 2) != 1) continue;
            UINT16 rr = pb_dns_u16(p + offset), bytes = pb_dns_u16(p + offset + 8);
            UINT32 ttl = pb_dns_u32(p + offset + 4); if (ttl > lifetime) ttl = lifetime;
            if (type == 1 && rr == 1 && bytes == 4) {
                UINT32 ip; memcpy(&ip, p + offset + 10, 4); dns_cache_store_ttl(ip, question, ttl);
            } else if (type == 28 && rr == 28 && bytes == 16)
                dns_cache_store_v6_ttl(p + offset + 10, question, ttl);
        }
        return;
    }
}

static void pb_dns_message(PB_DNS_TRACKER *t, BOOL response, const BYTE *p, UINT n)
{
    char name[256]; UINT16 type; int offset;
    if (!pb_dns_question(p, n, name, &type, &offset) ||
        (type != 1 && type != 28) || (pb_dns_u16(p + 2) & 0xFA0F) != (response ? 0x8000 : 0)) return;
    UINT16 id = pb_dns_u16(p); ULONGLONG now = GetTickCount64();
    if (!response) {
        PB_DNS_QUERY *q = &t->pending[t->next++ % PB_DNS_PENDING];
        q->id = id; q->type = type; q->expires = now + 10000;
        strcpy_s(q->name, sizeof(q->name), name);
    } else {
        for (UINT i = 0; i < PB_DNS_PENDING; ++i) {
            PB_DNS_QUERY *q = &t->pending[i];
            if (q->expires > now && q->id == id && q->type == type && !_stricmp(q->name, name)) {
                q->expires = 0; snoop_dns_response(p, n); return;
            }
        }
    }
}
void pb_dns_observe(PB_DNS_TRACKER *t, BOOL response, const BYTE *data, UINT size)
{
    if (!t) return;
    AcquireSRWLockExclusive(&t->lock);
    pb_dns_message(t, response, data, size);
    ReleaseSRWLockExclusive(&t->lock);
}
void pb_dns_stream(PB_DNS_TRACKER *t, BOOL response, const BYTE *data, UINT size)
{
    if (!t) return;
    AcquireSRWLockExclusive(&t->lock);
    PB_DNS_STREAM *s = &t->streams[response ? 1 : 0];
    if (!s->data && !s->disabled) { s->data = (BYTE *)malloc(PB_DNS_FRAME); s->needed = 2; }
    if (!s->data) s->disabled = TRUE;
    while (size && !s->disabled) {
        UINT take = s->needed - s->used; if (take > size) take = size;
        memcpy(s->data + s->used, data, take); s->used += take; data += take; size -= take;
        if (s->used != s->needed) continue;
        if (s->needed == 2) {
            s->needed = pb_dns_u16(s->data) + 2;
            if (s->needed < 14) s->disabled = TRUE;
        } else {
            pb_dns_message(t, response, s->data + 2, s->used - 2);
            s->used = 0; s->needed = 2;
        }
    }
    ReleaseSRWLockExclusive(&t->lock);
}
