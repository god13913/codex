namespace CodexProxySetup;

// PublicAudit compiles the storage helper in isolation. Keep only the scope
// constants it needs instead of pulling the Windows service implementation into
// the audit process.
internal static class RuntimeModeInstaller
{
    internal const string Service = "service";
    internal const string Desktop = "desktop";
}
