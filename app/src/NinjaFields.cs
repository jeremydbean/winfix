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
        private static readonly Dictionary<string, DateTime> emptySince = new Dictionary<string, DateTime>(StringComparer.Ordinal);
        private static readonly Dictionary<string, string> reasons = new Dictionary<string, string>(StringComparer.Ordinal);
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
                DateTime at;
                // Empty results are re-read after a minute, so a value filled in NinjaOne is picked up without restarting.
                if (cache.TryGetValue(name, out v) && (v.Length > 0 || (emptySince.TryGetValue(name, out at) && DateTime.UtcNow - at < TimeSpan.FromMinutes(1)))) return v;
                string why;
                v = Read(name, out why);
                cache[name] = v;
                reasons[name] = why;
                if (v.Length == 0) emptySince[name] = DateTime.UtcNow;
                return v;
            }
        }

        /// <summary>Forgets cached values (for example after a technician changed them in NinjaOne).</summary>
        public static void Refresh() { lock (gate) { cache.Clear(); emptySince.Clear(); reasons.Clear(); } }

        /// <summary>Why a field came back empty, for error messages ("" when it has a value).</summary>
        public static string Why(string name)
        {
            if (Value(name).Length > 0) return "";
            lock (gate) { string r; return reasons.TryGetValue(name, out r) ? r : ""; }
        }

        private static string Read(string name, out string why)
        {
            why = "";
            if (!AgentPresent) { why = "the NinjaOne agent is not installed on this computer, so the NinjaOne field " + name + " can't be read"; return ""; }
            try
            {
                // ninjarmm-cli writes to the console (WriteConsoleW) unless told otherwise, so captured output is
                // empty; --direct-out makes it use stdout. Agents too old for that option get a plain retry.
                int exit; string text, err;
                if (!Run("--direct-out get " + name, out exit, out text, out err)) { why = "reading the NinjaOne field " + name + " timed out"; return ""; }
                if (exit != 0 && !IsFieldError(text))
                {
                    if (!Run("get " + name, out exit, out text, out err)) { why = "reading the NinjaOne field " + name + " timed out"; return ""; }
                }
                if (exit != 0 || IsFieldError(text))
                {
                    string detail = (text.Length > 0 ? text : err).Split('\n')[0].Trim();
                    if (detail.Length > 120) detail = detail.Substring(0, 120);
                    Log.Write("NinjaOne field " + name + " not read (exit " + exit + "): " + detail);
                    why = "the NinjaOne field " + name + " couldn't be read" + (detail.Length > 0 ? " (" + detail + ")" : " (exit code " + exit + ")");
                    return "";
                }
                if (text.Length == 0) why = "the NinjaOne field " + name + " is empty in NinjaOne (Dashboard > Custom > Default fields)";
                return text;
            }
            catch (Exception ex) { Log.Write("NinjaOne field " + name + ": " + ex.Message); why = "the NinjaOne field " + name + " couldn't be read (" + ex.Message + ")"; return ""; }
        }

        private static bool IsFieldError(string text)
        {
            return text.StartsWith("Access to requested", StringComparison.OrdinalIgnoreCase) || text.StartsWith("Error", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>Runs ninjarmm-cli; false when it timed out.</summary>
        private static bool Run(string arguments, out int exit, out string stdout, out string stderr)
        {
            exit = -1; stdout = ""; stderr = "";
            var psi = new ProcessStartInfo(CliPath, arguments)
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
            };
            using (Process p = Process.Start(psi))
            {
                var o = p.StandardOutput.ReadToEndAsync();
                var e = p.StandardError.ReadToEndAsync();
                if (!p.WaitForExit(15000)) { try { p.Kill(); } catch { } Log.Write("ninjarmm-cli " + arguments.Split(' ')[0] + " timed out."); return false; }
                exit = p.ExitCode;
                stdout = (o.Result ?? "").Trim();
                stderr = (e.Result ?? "").Trim();
                return true;
            }
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
