ProxyBridge core source from InterceptSuite/ProxyBridge commit
02703a0672a8b94011a4698368a392f7734c10dc (MIT).
https://github.com/InterceptSuite/ProxyBridge/tree/02703a0672a8b94011a4698368a392f7734c10dc
Launch Deck modifications: narrowed capture, exclusive relay bind, five-tuple relay
validation, interruptible cleanup, checked joins, process-exit-safe DllMain and module pinning.
Codex dedicated modifications: an OS-assigned TCP relay port, HTTP 80 and HTTPS 443
capture, and a UDP 443 rule for the registered desktop path and owner SID. The
normal CLI supplies the authenticated loopback Mihomo endpoint to an elevated
instance of the same CLI; unmatched application packets retain their original path.
WinDivert 2.2.2-A binaries are retrieved separately and SHA256/signature checked.
The release links dynamically under WinDivert's LGPLv3 option; complete corresponding
WinDivert source and full license accompany each Enhanced release package.
