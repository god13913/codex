#include "pb_internal.h"

// DNS snoop cache: maps intercepted A/AAAA answers back to hostnames.

// dns cache
void dns_cache_init(void)
{
    InitializeSRWLock(&g_dns_cache_lock);
    memset(g_dns_cache,    0, sizeof(g_dns_cache));
    memset(g_dns_cache_v6, 0, sizeof(g_dns_cache_v6));
}

UINT32 dns_bucket(UINT32 ip)
{
    return (ip * 2654435761u) >> (32 - 10);  // Knuth multiplicative hash 1024 buckets
}

void dns_cache_store(UINT32 ip, const char *domain)
{
    dns_cache_store_ttl(ip, domain, DNS_CACHE_TTL_MS / 1000);
}

void dns_cache_store_ttl(UINT32 ip, const char *domain, UINT32 ttl)
{
    if (!domain || !pb_valid_hostname(domain)) return;
    ULONGLONG lifetime = (ULONGLONG)ttl * 1000;
    if (lifetime > DNS_CACHE_TTL_MS) lifetime = DNS_CACHE_TTL_MS;
    UINT32 bucket = dns_bucket(ip);
    ULONGLONG now = GetTickCount64();

    AcquireSRWLockExclusive(&g_dns_cache_lock);
    DNS_CACHE_ENTRY *e = g_dns_cache[bucket];
    while (e)
    {
        if (e->ip == ip)
        {
            if (e->expire_tick <= now) e->ambiguous = FALSE;
            else if (_stricmp(e->domain, domain)) e->ambiguous = TRUE;
            ULONGLONG expiry = now + lifetime;
            if (e->ambiguous && expiry < e->expire_tick) expiry = e->expire_tick;
            strncpy_s(e->domain, sizeof(e->domain), domain, _TRUNCATE);
            e->expire_tick = expiry;
            ReleaseSRWLockExclusive(&g_dns_cache_lock);
            return;
        }
        e = e->next;
    }
    DNS_CACHE_ENTRY *ne = (DNS_CACHE_ENTRY *)malloc(sizeof(DNS_CACHE_ENTRY));
    if (ne)
    {
        ne->ip         = ip;
        ne->expire_tick = now + lifetime;
        ne->ambiguous = FALSE;
        strncpy_s(ne->domain, sizeof(ne->domain), domain, _TRUNCATE);
        ne->next           = g_dns_cache[bucket];
        g_dns_cache[bucket] = ne;
    }
    ReleaseSRWLockExclusive(&g_dns_cache_lock);
}

BOOL dns_cache_lookup(UINT32 ip, char *out_domain, size_t out_size)
{
    UINT32 bucket = dns_bucket(ip);
    ULONGLONG now = GetTickCount64();
    BOOL found = FALSE;

    AcquireSRWLockShared(&g_dns_cache_lock);
    DNS_CACHE_ENTRY *e = g_dns_cache[bucket];
    while (e)
    {
        if (e->ip == ip && e->expire_tick > now && !e->ambiguous)
        {
            strncpy_s(out_domain, out_size, e->domain, _TRUNCATE);
            found = TRUE;
            break;
        }
        e = e->next;
    }
    ReleaseSRWLockShared(&g_dns_cache_lock);
    return found;
}

UINT32 dns_bucket_v6(const UINT8 ip6[16])
{
    // FNV-1a over 16 bytes, folded to DNS_CACHE_BUCKETS
    UINT32 h = 2166136261u;
    for (int i = 0; i < 16; i++)
        h = (h ^ ip6[i]) * 16777619u;
    return h & (DNS_CACHE_BUCKETS - 1);
}

void dns_cache_store_v6(const UINT8 ip6[16], const char *domain)
{
    dns_cache_store_v6_ttl(ip6, domain, DNS_CACHE_TTL_MS / 1000);
}

void dns_cache_store_v6_ttl(const UINT8 ip6[16], const char *domain, UINT32 ttl)
{
    if (!domain || !pb_valid_hostname(domain)) return;
    ULONGLONG lifetime = (ULONGLONG)ttl * 1000;
    if (lifetime > DNS_CACHE_TTL_MS) lifetime = DNS_CACHE_TTL_MS;
    UINT32 bucket = dns_bucket_v6(ip6);
    ULONGLONG now = GetTickCount64();

    AcquireSRWLockExclusive(&g_dns_cache_lock);
    DNS_CACHE_ENTRY_V6 *e = g_dns_cache_v6[bucket];
    while (e)
    {
        if (memcmp(e->ip6, ip6, 16) == 0)
        {
            if (e->expire_tick <= now) e->ambiguous = FALSE;
            else if (_stricmp(e->domain, domain)) e->ambiguous = TRUE;
            ULONGLONG expiry = now + lifetime;
            if (e->ambiguous && expiry < e->expire_tick) expiry = e->expire_tick;
            strncpy_s(e->domain, sizeof(e->domain), domain, _TRUNCATE);
            e->expire_tick = expiry;
            ReleaseSRWLockExclusive(&g_dns_cache_lock);
            return;
        }
        e = e->next;
    }
    DNS_CACHE_ENTRY_V6 *ne = (DNS_CACHE_ENTRY_V6 *)malloc(sizeof(DNS_CACHE_ENTRY_V6));
    if (ne)
    {
        memcpy(ne->ip6, ip6, 16);
        ne->expire_tick = now + lifetime;
        ne->ambiguous = FALSE;
        strncpy_s(ne->domain, sizeof(ne->domain), domain, _TRUNCATE);
        ne->next = g_dns_cache_v6[bucket];
        g_dns_cache_v6[bucket] = ne;
    }
    ReleaseSRWLockExclusive(&g_dns_cache_lock);
}

BOOL dns_cache_lookup_v6(const UINT8 ip6[16], char *out_domain, size_t out_size)
{
    UINT32 bucket = dns_bucket_v6(ip6);
    ULONGLONG now = GetTickCount64();
    BOOL found = FALSE;

    AcquireSRWLockShared(&g_dns_cache_lock);
    DNS_CACHE_ENTRY_V6 *e = g_dns_cache_v6[bucket];
    while (e)
    {
        if (memcmp(e->ip6, ip6, 16) == 0 && e->expire_tick > now && !e->ambiguous)
        {
            strncpy_s(out_domain, out_size, e->domain, _TRUNCATE);
            found = TRUE;
            break;
        }
        e = e->next;
    }
    ReleaseSRWLockShared(&g_dns_cache_lock);
    return found;
}

// Parse a DNS name (with pointer compression) at msg[*offset] into dst.
// Advances *offset past the name on success.
BOOL dns_parse_name(const UINT8 *msg, int msg_len, int *offset, char *dst, int dst_len)
{
    int pos    = *offset;
    int out    = 0;
    int jumps  = 0;
    BOOL jumped      = FALSE;
    int  jumped_end  = -1;

    while (pos < msg_len)
    {
        UINT8 b = msg[pos];
        if (b == 0x00)
        {
            dst[out] = '\0';
            if (!jumped) *offset = pos + 1;
            else         *offset = jumped_end;
            return TRUE;
        }
        if ((b & 0xC0) == 0xC0)
        {
            if (pos + 1 >= msg_len) return FALSE;
            if (!jumped) jumped_end = pos + 2;
            jumped = TRUE;
            pos = ((b & 0x3F) << 8) | msg[pos + 1];
            if (++jumps > 10) return FALSE;
            continue;
        }
        if (b & 0xC0) return FALSE;
        int label_len = (int)b;
        pos++;
        if (pos + label_len > msg_len)       return FALSE;
        if (out + label_len + 2 >= dst_len)  return FALSE;
        if (memchr(msg + pos, 0, label_len)) return FALSE;
        if (out > 0) dst[out++] = '.';
        memcpy(&dst[out], &msg[pos], label_len);
        out  += label_len;
        pos  += label_len;
    }
    return FALSE;
}

// Learning is restricted to DNS payloads on proxy-matched application flows.
// In particular, no system-wide inbound port-53 capture is installed.
#include "pb_dns_track.c"

// Prune expired DNS-snoop entries (IPv4 + IPv6) so the caches don't grow without bound.
void cleanup_stale_dns_cache(void)
{
    ULONGLONG now = GetTickCount64();

    AcquireSRWLockExclusive(&g_dns_cache_lock);
    for (int i = 0; i < DNS_CACHE_BUCKETS; i++)
    {
        DNS_CACHE_ENTRY **pp = &g_dns_cache[i];
        while (*pp != NULL)
        {
            if ((*pp)->expire_tick <= now)
            {
                DNS_CACHE_ENTRY *to_free = *pp;
                *pp = (*pp)->next;
                free(to_free);
            }
            else
            {
                pp = &(*pp)->next;
            }
        }

        DNS_CACHE_ENTRY_V6 **pp6 = &g_dns_cache_v6[i];
        while (*pp6 != NULL)
        {
            if ((*pp6)->expire_tick <= now)
            {
                DNS_CACHE_ENTRY_V6 *to_free = *pp6;
                *pp6 = (*pp6)->next;
                free(to_free);
            }
            else
            {
                pp6 = &(*pp6)->next;
            }
        }
    }
    ReleaseSRWLockExclusive(&g_dns_cache_lock);
}

// Flush the Windows DNS resolver cache so applications re-resolve hostnames on the
// wire, where our port-53 snoop can capture the IP->hostname mapping. Without this a
// domain that was resolved before a domain rule existed would have no cached mapping
// and the rule could not match. DnsFlushResolverCache is loaded dynamically so we
// avoid a hard dnsapi.lib dependency (keeps the MinGW/GCC build path unchanged).
void flush_dns_resolver_cache(void)
{
    HMODULE dnsapi = LoadLibraryA("dnsapi.dll");
    if (dnsapi == NULL)
        return;
    typedef BOOL (WINAPI *DnsFlushFn)(void);
    DnsFlushFn fn = (DnsFlushFn)GetProcAddress(dnsapi, "DnsFlushResolverCache");
    if (fn != NULL)
        fn();
    FreeLibrary(dnsapi);
}
