using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

namespace PolarniteAudit
{
    /// <summary>
    /// Shared settings kept in NinjaOne device custom fields (normal text fields, inherited from the
    /// system or organization level), read through the NinjaOne agent's ninjarmm-cli on this server.
    /// A value set in NinjaOne overrides the same setting in the app's Settings window.
    /// </summary>
    internal static class NinjaFields
    {
        public const string SmtpUser = "smtp2goUsername";
        public const string SmtpPassword = "smtp2goPassword";
        public const string SmtpFrom = "smtp2goFromAddress";
        public const string ApiClientId = "ninjaApiClientId";
        public const string ApiClientSecret = "ninjaApiClientSecret";

        private static readonly Dictionary<string, string> cache = new Dictionary<string, string>(StringComparer.Ordinal);
        private static readonly object gate = new object();

        /// <summary>ninjarmm-cli.exe; POLARNITE_NINJA_CLI points elsewhere for tests.</summary>
        public static string CliPath
        {
            get
            {
                string o = Environment.GetEnvironmentVariable("POLARNITE_NINJA_CLI");
                if (!string.IsNullOrEmpty(o)) return o;
                return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"NinjaRMMAgent\ninjarmm-cli.exe");
            }
        }

        public static bool AgentPresent { get { return File.Exists(CliPath); } }

        /// <summary>The field's value, or "" when the agent is missing, the field is empty or it cannot be read.</summary>
        public static string Value(string name)
        {
            lock (gate)
            {
                string v;
                if (cache.TryGetValue(name, out v)) return v;
                v = Read(name);
                cache[name] = v;
                return v;
            }
        }

        /// <summary>Forgets cached values (for example after a technician changed them in NinjaOne).</summary>
        public static void Refresh() { lock (gate) cache.Clear(); }

        private static string Read(string name)
        {
            if (!AgentPresent) return "";
            try
            {
                var psi = new ProcessStartInfo(CliPath, "get " + name)
                {
                    UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
                };
                using (Process p = Process.Start(psi))
                {
                    var stdout = p.StandardOutput.ReadToEndAsync();
                    var stderr = p.StandardError.ReadToEndAsync();
                    if (!p.WaitForExit(15000)) { try { p.Kill(); } catch { } Log.Write("NinjaOne field " + name + ": ninjarmm-cli timed out."); return ""; }
                    string text = (stdout.Result ?? "").Trim();
                    if (p.ExitCode != 0 || text.StartsWith("Access to requested", StringComparison.OrdinalIgnoreCase) || text.StartsWith("Error", StringComparison.OrdinalIgnoreCase))
                    {
                        if (text.Length > 0 || (stderr.Result ?? "").Trim().Length > 0) Log.Write("NinjaOne field " + name + " not read (exit " + p.ExitCode + ").");
                        return "";
                    }
                    return text;
                }
            }
            catch (Exception ex) { Log.Write("NinjaOne field " + name + ": " + ex.Message); return ""; }
        }

        /// <summary>Which shared settings came from NinjaOne, for the Settings window.</summary>
        public static string Summary()
        {
            if (!AgentPresent) return "NinjaOne agent not found on this server; using the values below.";
            var found = new List<string>();
            if (Value(SmtpUser).Length > 0) found.Add("SMTP username");
            if (Value(SmtpPassword).Length > 0) found.Add("SMTP password");
            if (Value(SmtpFrom).Length > 0) found.Add("From address");
            if (Value(ApiClientId).Length > 0 && Value(ApiClientSecret).Length > 0) found.Add("NinjaOne API key");
            return found.Count == 0 ? "None of these fields are set in NinjaOne; using the values below."
                                    : "From NinjaOne (overrides the values below): " + string.Join(", ", found.ToArray()) + ".";
        }
    }
}
