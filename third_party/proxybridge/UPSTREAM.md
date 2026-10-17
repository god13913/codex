ProxyBridge core source from InterceptSuite/ProxyBridge commit
02703a0672a8b94011a4698368a392f7734c10dc (MIT).
https://github.com/InterceptSuite/ProxyBridge/tree/02703a0672a8b94011a4698368a392f7734c10dc
Launch Deck modifications: narrowed capture, exclusive relay bind, five-tuple relay
validation, interruptible cleanup, checked joins, process-exit-safe DllMain and module pinning.
Codex dedicated modifications: an OS-assigned TCP relay port, HTTP 80 and HTTPS 443
capture, matched-process TCP DNS (53), and outbound UDP forwarding for the registered
desktop/CLI paths and owner SID. The system DNS service remains outside these rules. The
normal CLI supplies the authenticated loopback Mihomo endpoint to an elevated
instance of the same CLI; unmatched application packets retain their original path.
Transport fixes: bounded incremental CONNECT headers without consuming tunnel data,
TCP half-close preservation, interruptible relay reads/writes and a shared abort flag,
plus FIN/RST tracking grace and SYN-based port reuse detection. Local standalone
transport tests never start interception or load the WinDivert driver.
UDP uses an authenticated loopback SOCKS5 mixed listener, one association per complete
application tuple, bounded queues and idle lifetime, checked IPv4/IPv6 replies and
interruptible shutdown. Matched transport/configuration/authentication failures drop
packets instead of releasing them directly. QUIC and voice may fall back to TCP in
the application when the selected upstream node does not support UDP.
WinDivert 2.2.2-A binaries are retrieved separately and SHA256/signature checked.
The release links dynamically under WinDivert's LGPLv3 option; complete corresponding
WinDivert source and full license accompany each Enhanced release package.

First-request service integration adds an explicit upstream-ready gate before TCP/UDP
workers dial the authenticated local proxy. Domain forwarding learns only matched
application DNS transactions (UDP and framed TCP), checks CNAME ownership and TTL,
and rejects ambiguous shared-IP cache hits. Bounded, non-consuming TLS SNI / HTTP
Host inspection overrides IP cache guesses without changing application bytes.
System DNS service traffic is not snooped or redirected.

UDP capture includes packets reinjected by other WFP drivers (Impostor flag).
Excluding those packets can leak QUIC Initial outside the proxy while later
handshake/data packets use SOCKS, splitting a single connection across routes.
Process/owner rules remain mandatory; loopback, inbound UDP replies and DHCP
remain outside capture. The existing TCP impostor exclusion is unchanged.
