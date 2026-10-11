// Build-only helper: cache Cargo's pinned Git dependencies without downloading their entire history.
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

class GitFetchShim {
    static string Quote(string value) {
        var output = new StringBuilder("\"");
        int slashes = 0;
        foreach (char character in value) {
            if (character == '\\') { slashes++; continue; }
            if (character == '"') { output.Append('\\', slashes * 2 + 1); }
            else { output.Append('\\', slashes); }
            output.Append(character); slashes = 0;
        }
        output.Append('\\', slashes * 2); output.Append('"');
        return output.ToString();
    }
    static int Main(string[] arguments) {
        string git = Environment.GetEnvironmentVariable("CODEX_BUILD_REAL_GIT");
        if (String.IsNullOrEmpty(git)) { Console.Error.WriteLine("Missing real Git path"); return 1; }
        if (String.Equals(Path.GetFullPath(git), Process.GetCurrentProcess().MainModule.FileName, StringComparison.OrdinalIgnoreCase)) {
            Console.Error.WriteLine("Build Git helper cannot forward to itself"); return 1;
        }
        if (arguments.Length > 0 && arguments[0] == "fetch" && !arguments.Any(value => value.StartsWith("--depth"))) {
            arguments = new[] { "fetch", "--depth=1" }.Concat(arguments.Skip(1)).ToArray();
        }
        var start = new ProcessStartInfo(git, String.Join(" ", arguments.Select(Quote))) {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true
        };
        using (var child = Process.Start(start)) {
            child.OutputDataReceived += (sender, data) => { if (data.Data != null) Console.Out.WriteLine(data.Data); };
            child.ErrorDataReceived += (sender, data) => { if (data.Data != null) Console.Error.WriteLine(data.Data); };
            child.BeginOutputReadLine(); child.BeginErrorReadLine();
            child.WaitForExit(); return child.ExitCode;
        }
    }
}
