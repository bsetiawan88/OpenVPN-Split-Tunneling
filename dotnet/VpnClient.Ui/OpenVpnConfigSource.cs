using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace VpnClient.Ui;

/// <summary>
/// Source of truth for VPN profiles: the OpenVPN Community config dir.
/// No import/copy step — we read *.ovpn straight from
/// C:\Program Files\OpenVPN\config (plus the x86 twin). Saved JSON only
/// contributes per-file credentials + server override, matched by path.
/// </summary>
public static class OpenVpnConfigSource
{
    public static readonly string[] ConfigDirs =
    {
        @"C:\Program Files\OpenVPN\config",
        @"C:\Program Files (x86)\OpenVPN\config",
    };

    /// <summary>
    /// Scan the OpenVPN config dirs for *.ovpn and merge saved credentials.
    /// New files get a fresh Id; known paths keep their saved Id/creds.
    /// </summary>
    public static List<OvpnEntry> Scan(IEnumerable<OvpnEntry>? saved = null)
    {
        var savedByPath = new Dictionary<string, OvpnEntry>(StringComparer.OrdinalIgnoreCase);
        if (saved is not null)
        {
            foreach (var s in saved)
            {
                if (!string.IsNullOrWhiteSpace(s.FilePath))
                    savedByPath[s.FilePath] = s;
            }
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var out_ = new List<OvpnEntry>();

        foreach (var dir in ConfigDirs)
        {
            string[] files;
            try
            {
                if (!Directory.Exists(dir)) continue;
                files = Directory.GetFiles(dir, "*.ovpn", SearchOption.AllDirectories);
            }
            catch
            {
                continue;
            }

            Array.Sort(files, StringComparer.OrdinalIgnoreCase);
            foreach (var file in files)
            {
                if (!seen.Add(file)) continue;

                savedByPath.TryGetValue(file, out var prev);
                var remote = OvpnParser.ParseRemote(file) ?? "";
                var display = DisplayNameFor(dir, file);

                out_.Add(new OvpnEntry
                {
                    Id = prev?.Id ?? Guid.NewGuid().ToString("N"),
                    DisplayName = prev?.DisplayName ?? display,
                    FilePath = file,
                    ServerHostname = remote,
                    ServerOverride = prev?.ServerOverride ?? "",
                    Username = prev?.Username ?? "",
                    PasswordEncrypted = prev?.PasswordEncrypted ?? "",
                    ImportedAt = prev?.ImportedAt ?? DateTime.UtcNow,
                });
            }
        }

        return out_;
    }

    private static string DisplayNameFor(string rootDir, string file)
    {
        try
        {
            var rel = Path.GetRelativePath(rootDir, file);
            var noExt = Path.ChangeExtension(rel, null) ?? rel;
            // "jp-tokyo/foo" -> "jp-tokyo / foo" for readability.
            return noExt.Replace(Path.DirectorySeparatorChar, '/').Replace("/", " / ");
        }
        catch
        {
            return Path.GetFileNameWithoutExtension(file);
        }
    }

    public static string DescribeDirs() => string.Join("; ", ConfigDirs);
}
