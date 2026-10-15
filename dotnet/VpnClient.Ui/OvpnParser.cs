using System;
using System.IO;

namespace VpnClient.Ui;

public static class OvpnParser
{
    /// <summary>
    /// Pulls the first `remote &lt;host&gt; [&lt;port&gt;]` line out of an .ovpn config and
    /// returns the hostname only (matches OpenVPN Connect's display convention).
    /// Returns null if no remote line found.
    /// </summary>
    public static string? ParseRemote(string filePath)
    {
        try
        {
            foreach (var raw in File.ReadAllLines(filePath))
            {
                var line = raw.Trim();
                if (line.StartsWith("#") || line.StartsWith(";")) continue;
                if (!line.StartsWith("remote ", StringComparison.OrdinalIgnoreCase)) continue;
                var parts = line.Split(
                    (char[]?)null,
                    StringSplitOptions.RemoveEmptyEntries
                );
                if (parts.Length >= 2) return parts[1];
            }
        }
        catch
        {
            // fall through
        }
        return null;
    }

    /// <summary>
    /// True when the .ovpn requests username/password auth (has an
    /// `auth-user-pass` directive, with or without an inline file arg).
    /// Used to decide whether --auth-user-pass must be passed to openvpn.
    /// </summary>
    public static bool RequiresAuth(string filePath)
    {
        return GetAuthMode(filePath) != OvpnAuthMode.None;
    }

    /// <summary>
    /// True only when the credentials MUST come from our UI: the .ovpn asks
    /// for auth but carries no usable credential of its own (bare directive,
    /// reference to a missing file, or an empty inline block).
    /// Profiles with an existing auth file or a filled inline block must NOT
    /// be forced through the UI — and our CLI flag must not override them.
    /// </summary>
    public static bool NeedsUiCredentials(string filePath)
    {
        return GetAuthMode(filePath) switch
        {
            OvpnAuthMode.Bare => true,
            OvpnAuthMode.ExternalFileMissing => true,
            OvpnAuthMode.InlineEmpty => true,
            _ => false,
        };
    }

    public enum OvpnAuthMode
    {
        /// <summary>No auth-user-pass anywhere: cert-only profile.</summary>
        None,
        /// <summary>Bare `auth-user-pass` line: credentials must be supplied.</summary>
        Bare,
        /// <summary>`auth-user-pass &lt;file&gt;` where the file exists.</summary>
        ExternalFile,
        /// <summary>`auth-user-pass &lt;file&gt;` but the file is missing.</summary>
        ExternalFileMissing,
        /// <summary>Inline &lt;auth-user-pass&gt; block containing credentials.</summary>
        Inline,
        /// <summary>Inline block present but empty.</summary>
        InlineEmpty,
    }

    /// <summary>
    /// Classify how the .ovpn provides (or fails to provide) auth credentials.
    /// Relative auth-file paths resolve against the .ovpn's own folder.
    /// </summary>
    public static OvpnAuthMode GetAuthMode(string filePath)
    {
        string[] lines;
        try { lines = File.ReadAllLines(filePath); }
        catch { return OvpnAuthMode.None; }

        var dir = Path.GetDirectoryName(filePath) ?? "";
        var mode = OvpnAuthMode.None;

        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (line.StartsWith("#") || line.StartsWith(";")) continue;

            if (IsDirective(line, "<auth-user-pass>", out _))
            {
                var credLines = 0;
                i++;
                for (; i < lines.Length; i++)
                {
                    var inner = lines[i].Trim();
                    if (IsDirective(inner, "</auth-user-pass>", out _))
                        break;
                    if (inner.Length == 0 || inner.StartsWith("#") || inner.StartsWith(";"))
                        continue;
                    credLines++;
                }
                mode = credLines >= 2 ? OvpnAuthMode.Inline : OvpnAuthMode.InlineEmpty;
            }
            else if (IsDirective(line, "auth-user-pass", out var rest))
            {
                var ref_path = FirstToken(rest);
                if (string.IsNullOrEmpty(ref_path))
                {
                    mode = OvpnAuthMode.Bare;
                }
                else
                {
                    var full = Path.IsPathRooted(ref_path)
                        ? ref_path
                        : Path.Combine(dir, ref_path);
                    mode = File.Exists(full) ? OvpnAuthMode.ExternalFile : OvpnAuthMode.ExternalFileMissing;
                }
            }
        }
        return mode;
    }

    /// <summary>
    /// True when the line is exactly the named directive: whole first token,
    /// case-insensitive. A mere prefix does NOT match, so server-side
    /// directives like `auth-user-pass-verify` never false-positive.
    /// Returns the remainder of the line after the directive name.
    /// </summary>
    private static bool IsDirective(string line, string name, out string rest)
    {
        rest = "";
        var t = line.TrimStart();
        if (t.Length < name.Length) return false;
        if (!t.StartsWith(name, StringComparison.OrdinalIgnoreCase)) return false;
        if (t.Length == name.Length) return true;
        var c = t[name.Length];
        if (c != ' ' && c != '\t') return false;
        rest = t[name.Length..].TrimStart();
        return true;
    }

    /// <summary>
    /// First whitespace-delimited token, honoring "double" and 'single'
    /// quoting so paths with spaces survive intact.
    /// </summary>
    private static string FirstToken(string rest)
    {
        var s = rest.TrimStart();
        if (s.Length == 0) return "";
        if (s[0] == '"' || s[0] == '\'')
        {
            var q = s[0];
            var end = s.IndexOf(q, 1);
            return end < 0 ? s[1..] : s[1..end];
        }
        var ws = s.IndexOfAny(new[] { ' ', '\t' });
        return ws < 0 ? s : s[..ws];
    }
}
