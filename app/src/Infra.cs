using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace WinFixAudit
{
    internal static class AppPaths
    {
        // WINFIXAUDIT_DATA redirects all state (used by tests); normally C:\ProgramData\WinFixAudit.
        public static string Root = string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WINFIXAUDIT_DATA"))
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WinFixAudit")
            : Environment.GetEnvironmentVariable("WINFIXAUDIT_DATA");
        public static string SettingsFile { get { return Path.Combine(Root, "settings.json"); } }
        public static string StateDir { get { return Path.Combine(Root, "state"); } }
        public static string DraftFile { get { return Path.Combine(StateDir, "current.json"); } }
        public static string LastAnswersFile { get { return Path.Combine(StateDir, "last-answers.json"); } }
        public static string HistoryDir { get { return Path.Combine(StateDir, "history"); } }
        public static string RunsDir { get { return Path.Combine(Root, "runs"); } }
        public static string LogsDir { get { return Path.Combine(Root, "logs"); } }
        public static string BinDir { get { return Path.Combine(Root, "bin"); } }
        public static string InstalledExe { get { return Path.Combine(BinDir, "WinFixAuditApp.exe"); } }

        /// <summary>Creates the data folder and limits it to Administrators and SYSTEM (it holds the SMTP secret and audit data).</summary>
        public static void EnsureRoot()
        {
            bool created = !Directory.Exists(Root);
            Directory.CreateDirectory(Root);
            if (created && string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WINFIXAUDIT_DATA"))) Harden(Root);
            foreach (string d in new[] { StateDir, HistoryDir, RunsDir, LogsDir, BinDir }) Directory.CreateDirectory(d);
        }

        public static void Harden(string dir)
        {
            try
            {
                var sec = new DirectorySecurity();
                sec.SetAccessRuleProtection(true, false);
                var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
                sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
                sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
                Directory.SetAccessControl(dir, sec);
            }
            catch (Exception ex) { Log.Write("Could not restrict permissions on " + dir + ": " + ex.Message); }
        }
    }

    internal static class Log
    {
        private static readonly object Gate = new object();
        public static void Write(string message)
        {
            try
            {
                lock (Gate)
                {
                    Directory.CreateDirectory(AppPaths.LogsDir);
                    string file = Path.Combine(AppPaths.LogsDir, "app-" + DateTime.Now.ToString("yyyy-MM", CultureInfo.InvariantCulture) + ".log");
                    File.AppendAllText(file, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + "  " + message + Environment.NewLine);
                }
            }
            catch { }
        }
    }

    internal static class JsonFile
    {
        public static object Read(string path)
        {
            return File.Exists(path) ? J.Parse(File.ReadAllText(path, Encoding.UTF8)) : null;
        }

        public static void Write(string path, object value)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            string tmp = path + ".tmp";
            File.WriteAllText(tmp, J.Serialize(value), new UTF8Encoding(false));
            if (File.Exists(path)) File.Replace(tmp, path, null);
            else File.Move(tmp, path);
        }
    }

    internal sealed class AppSettings
    {
        public string SmtpHost = "";
        public int SmtpPort = 587;
        public bool SmtpStartTls = true;
        public string SmtpUser = "";
        public string SmtpPasswordProtected = "";
        public string FromAddress = "";
        public string FromName = "Server Audit";
        public string ToAddress = "support@polarnite.com";
        public string CompanyName = "Polarnite";
        public string DefaultTenant = "";
        public string ExpectedAgents = "Ninja, Huntress";
        public string SubjectTemplate = "Monthly Server Audit - {tenant} - {server} - {month}";
        public bool DeepAudit = false;
        public bool OnlineUpdateScan = true;
        public bool ExternalExposureCheck = false;
        public int ScheduleDay = 1;
        public string ScheduleTime = "06:00";
        public int KeepRunsMonths = 6;
        public string LastTechnician = "";

        private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("WinFixAudit-SMTP-v1");

        public string[] ExpectedAgentList
        {
            get { return (ExpectedAgents ?? "").Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim()).Where(s => s.Length > 0).ToArray(); }
        }

        /// <summary>Machine-scoped DPAPI: readable by this computer only, so the GUI and a SYSTEM task share it.</summary>
        public string SmtpPassword
        {
            get
            {
                if (string.IsNullOrEmpty(SmtpPasswordProtected)) return "";
                try { return Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(SmtpPasswordProtected), Entropy, DataProtectionScope.LocalMachine)); }
                catch (Exception ex) { Log.Write("SMTP password could not be decrypted: " + ex.Message); return ""; }
            }
            set
            {
                SmtpPasswordProtected = string.IsNullOrEmpty(value) ? "" :
                    Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(value), Entropy, DataProtectionScope.LocalMachine));
            }
        }

        public static AppSettings Load()
        {
            var s = new AppSettings();
            object o;
            try { o = JsonFile.Read(AppPaths.SettingsFile); }
            catch (Exception ex) { Log.Write("Settings unreadable, using defaults: " + ex.Message); return s; }
            if (o == null) return s;
            s.SmtpHost = J.Str(o, "SmtpHost");
            s.SmtpPort = (int)(J.Num(o, "SmtpPort") ?? 587);
            s.SmtpStartTls = J.Bool(o, "SmtpStartTls") ?? true;
            s.SmtpUser = J.Str(o, "SmtpUser");
            s.SmtpPasswordProtected = J.Str(o, "SmtpPasswordProtected");
            s.FromAddress = J.Str(o, "FromAddress");
            s.FromName = Or(J.Str(o, "FromName"), s.FromName);
            s.ToAddress = Or(J.Str(o, "ToAddress"), s.ToAddress);
            s.CompanyName = Or(J.Str(o, "CompanyName"), s.CompanyName);
            s.DefaultTenant = J.Str(o, "DefaultTenant");
            if (J.Get(o, "ExpectedAgents") != null) s.ExpectedAgents = J.Str(o, "ExpectedAgents");
            s.SubjectTemplate = Or(J.Str(o, "SubjectTemplate"), s.SubjectTemplate);
            s.DeepAudit = J.Bool(o, "DeepAudit") ?? false;
            s.OnlineUpdateScan = J.Bool(o, "OnlineUpdateScan") ?? true;
            s.ExternalExposureCheck = J.Bool(o, "ExternalExposureCheck") ?? false;
            s.ScheduleDay = (int)(J.Num(o, "ScheduleDay") ?? 1);
            s.ScheduleTime = Or(J.Str(o, "ScheduleTime"), "06:00");
            s.KeepRunsMonths = (int)(J.Num(o, "KeepRunsMonths") ?? 6);
            s.LastTechnician = J.Str(o, "LastTechnician");
            return s;
        }

        public void Save()
        {
            AppPaths.EnsureRoot();
            JsonFile.Write(AppPaths.SettingsFile, new Dictionary<string, object>
            {
                { "SmtpHost", SmtpHost }, { "SmtpPort", SmtpPort }, { "SmtpStartTls", SmtpStartTls }, { "SmtpUser", SmtpUser },
                { "SmtpPasswordProtected", SmtpPasswordProtected }, { "FromAddress", FromAddress }, { "FromName", FromName },
                { "ToAddress", ToAddress }, { "CompanyName", CompanyName }, { "DefaultTenant", DefaultTenant },
                { "ExpectedAgents", ExpectedAgents }, { "SubjectTemplate", SubjectTemplate }, { "DeepAudit", DeepAudit },
                { "OnlineUpdateScan", OnlineUpdateScan }, { "ExternalExposureCheck", ExternalExposureCheck }, { "ScheduleDay", ScheduleDay }, { "ScheduleTime", ScheduleTime },
                { "KeepRunsMonths", KeepRunsMonths }, { "LastTechnician", LastTechnician }
            });
        }

        public List<string> ValidateMail()
        {
            var p = new List<string>();
            if (string.IsNullOrWhiteSpace(SmtpHost)) p.Add("SMTP server is not set (Settings).");
            if (SmtpPort == 465) p.Add("Port 465 (implicit TLS) is not supported. Use 587 with STARTTLS, or 25.");
            if (!IsEmail(FromAddress)) p.Add("From address is not a valid email address (Settings).");
            if (!IsEmail(ToAddress)) p.Add("Ticket address is not a valid email address (Settings).");
            return p;
        }

        public static bool IsEmail(string s)
        {
            return !string.IsNullOrWhiteSpace(s) && Regex.IsMatch(s.Trim(), @"^[^@\s]+@[^@\s]+\.[^@\s]+$");
        }

        private static string Or(string a, string b) { return string.IsNullOrEmpty(a) ? b : a; }
    }

    internal static class DraftStore
    {
        public static DraftState Load()
        {
            try { object o = JsonFile.Read(AppPaths.DraftFile); return o == null ? null : DraftState.FromDict(o); }
            catch (Exception ex) { Log.Write("Draft unreadable: " + ex.Message); return null; }
        }

        public static void Save(DraftState d)
        {
            AppPaths.EnsureRoot();
            JsonFile.Write(AppPaths.DraftFile, d.ToDict());
        }

        public static DraftState LoadLastAnswers()
        {
            try { object o = JsonFile.Read(AppPaths.LastAnswersFile); return o == null ? null : DraftState.FromDict(o); }
            catch { return null; }
        }

        /// <summary>Records a submitted audit: last answers for next month's prefill and a history copy.</summary>
        public static void RecordSubmission(DraftState d)
        {
            JsonFile.Write(AppPaths.LastAnswersFile, d.ToDict());
            string name = "submitted-" + (string.IsNullOrEmpty(d.MonthKey) ? "unknown" : d.MonthKey) + "-" + DateTime.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + ".json";
            JsonFile.Write(Path.Combine(AppPaths.HistoryDir, name), d.ToDict());
        }

        /// <summary>A new month's draft: previous identity fields and notes carried forward, statuses reset.</summary>
        public static DraftState NewDraft(string reportPath, AuditAnalysis a, AppSettings s, string source)
        {
            var d = new DraftState { ReportPath = reportPath, MonthKey = a.MonthKey, Source = source, CreatedAt = DateTime.Now.ToString("o", CultureInfo.InvariantCulture) };
            DraftState last = LoadLastAnswers();
            d.Tenant = !string.IsNullOrEmpty(last == null ? "" : last.Tenant) ? last.Tenant : (!string.IsNullOrEmpty(s.DefaultTenant) ? s.DefaultTenant : a.DefaultTenant);
            d.Technician = s.LastTechnician;
            if (last != null)
            {
                d.ServerPurpose = last.ServerPurpose;
                foreach (var kv in last.Manual) d.Manual[kv.Key] = new ManualAnswer { Status = ManualCatalog.NotChecked, Notes = kv.Value.Notes };
            }
            return d;
        }
    }

    internal sealed class CollectorOptions
    {
        public bool DeepAudit;
        public bool OnlineUpdateScan = true;
        public bool ExternalExposureCheck;
    }

    /// <summary>Runs the embedded Export-WinFixAudit.ps1 in Windows PowerShell and returns the report path.</summary>
    internal static class CollectorRunner
    {
        public const string ResourceName = "Export-WinFixAudit.ps1";

        public static string CollectorVersion()
        {
            using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream(ResourceName))
            {
                if (s == null) return "missing";
                using (var r = new StreamReader(s))
                {
                    Match m = Regex.Match(r.ReadToEnd(), @"WinFix audit (\d+(\.\d+)*)");
                    return m.Success ? m.Groups[1].Value : "unknown";
                }
            }
        }

        private static string PowerShellPath()
        {
            string windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string sub = Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess ? "Sysnative" : "System32";
            return Path.Combine(windir, sub, @"WindowsPowerShell\v1.0\powershell.exe");
        }

        public static string Run(CollectorOptions options, Action<string> onLine, CancellationToken cancel)
        {
            AppPaths.EnsureRoot();
            string runDir = Path.Combine(AppPaths.RunsDir, DateTime.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture));
            Directory.CreateDirectory(runDir);
            string script = Path.Combine(runDir, ResourceName);
            using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream(ResourceName))
            {
                if (s == null) throw new InvalidOperationException("The audit collector is not embedded in this build.");
                using (var f = File.Create(script)) s.CopyTo(f);
            }

            var args = new StringBuilder("-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + script + "\" -NoOpen -OutputDirectory \"" + runDir + "\"");
            if (options.DeepAudit) args.Append(" -DeepAudit");
            if (!options.OnlineUpdateScan) args.Append(" -SkipOnlineUpdateScan");
            if (options.ExternalExposureCheck) args.Append(" -ExternalExposureCheck");

            var psi = new ProcessStartInfo(PowerShellPath(), args.ToString())
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
                WorkingDirectory = runDir, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8
            };
            Log.Write("Starting collector in " + runDir);
            using (var p = new Process { StartInfo = psi })
            {
                p.OutputDataReceived += (o, e) => { if (e.Data != null) onLine(e.Data); };
                p.ErrorDataReceived += (o, e) => { if (!string.IsNullOrWhiteSpace(e.Data)) onLine("ERROR: " + e.Data); };
                p.Start();
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();
                while (!p.WaitForExit(500))
                {
                    if (cancel.IsCancellationRequested)
                    {
                        KillTree(p.Id);
                        p.WaitForExit(10000);
                        onLine("Audit cancelled.");
                        break;
                    }
                }
                p.WaitForExit();
                Log.Write("Collector exited with code " + (p.HasExited ? p.ExitCode.ToString(CultureInfo.InvariantCulture) : "?"));
            }
            try { File.Delete(script); } catch { }
            string report = FindReport(runDir);
            if (report == null) throw new InvalidOperationException("The collector did not produce a report. See the Collection log tab.");
            return report;
        }

        public static string FindReport(string dir)
        {
            var files = Directory.GetFiles(dir, "WinFixAudit-*.json").Where(f => !f.EndsWith("-EVIDENCE-TEMPLATE.json", StringComparison.OrdinalIgnoreCase)).ToList();
            string final = files.Where(f => !f.EndsWith("-PARTIAL.json", StringComparison.OrdinalIgnoreCase)).OrderByDescending(File.GetLastWriteTimeUtc).FirstOrDefault();
            return final ?? files.OrderByDescending(File.GetLastWriteTimeUtc).FirstOrDefault();
        }

        private static void KillTree(int pid)
        {
            try
            {
                var k = Process.Start(new ProcessStartInfo("taskkill.exe", "/PID " + pid + " /T /F") { UseShellExecute = false, CreateNoWindow = true });
                if (k != null) k.WaitForExit(15000);
            }
            catch (Exception ex) { Log.Write("taskkill failed: " + ex.Message); }
        }

        /// <summary>Deletes old run folders, keeping the one the current draft uses.</summary>
        public static void PruneRuns(int keepMonths, string keepReport)
        {
            try
            {
                DateTime cutoff = DateTime.Now.AddMonths(-Math.Max(1, keepMonths));
                string keepDir = string.IsNullOrEmpty(keepReport) ? "" : Path.GetDirectoryName(keepReport);
                foreach (string dir in Directory.GetDirectories(AppPaths.RunsDir))
                {
                    if (string.Equals(dir, keepDir, StringComparison.OrdinalIgnoreCase)) continue;
                    if (Directory.GetCreationTime(dir) < cutoff) Directory.Delete(dir, true);
                }
            }
            catch (Exception ex) { Log.Write("Prune failed: " + ex.Message); }
        }
    }

    internal static class Scheduler
    {
        public const string TaskName = @"\WinFix\Monthly Server Audit";

        private static string Run(string args, out int exitCode)
        {
            var psi = new ProcessStartInfo("schtasks.exe", args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            using (Process p = Process.Start(psi))
            {
                string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                p.WaitForExit();
                exitCode = p.ExitCode;
                return output.Trim();
            }
        }

        /// <summary>Copies this exe to ProgramData and registers a monthly SYSTEM task that collects and saves a draft.</summary>
        public static string Install(AppSettings s)
        {
            AppPaths.EnsureRoot();
            string self = Assembly.GetExecutingAssembly().Location;
            if (!string.Equals(Path.GetFullPath(self), Path.GetFullPath(AppPaths.InstalledExe), StringComparison.OrdinalIgnoreCase))
                File.Copy(self, AppPaths.InstalledExe, true);
            int day = Math.Max(1, Math.Min(28, s.ScheduleDay));
            DateTime t;
            if (!DateTime.TryParseExact(s.ScheduleTime, "HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out t))
                throw new ArgumentException("Schedule time must be HH:mm (24-hour).");
            string args = "/Create /F /TN \"" + TaskName + "\" /TR \"\\\"" + AppPaths.InstalledExe + "\\\" --scheduled\" /SC MONTHLY /D " + day +
                " /ST " + t.ToString("HH:mm", CultureInfo.InvariantCulture) + " /RU SYSTEM /RL HIGHEST";
            int code;
            string output = Run(args, out code);
            Log.Write("schtasks create: " + code + " " + output);
            if (code != 0) throw new InvalidOperationException("schtasks failed: " + output);
            return "Runs on day " + day + " of each month at " + t.ToString("HH:mm", CultureInfo.InvariantCulture) + " as SYSTEM.";
        }

        public static void Remove()
        {
            int code;
            string output = Run("/Delete /F /TN \"" + TaskName + "\"", out code);
            Log.Write("schtasks delete: " + code + " " + output);
            if (code != 0) throw new InvalidOperationException("schtasks failed: " + output);
        }

        public static string Status()
        {
            int code;
            string output = Run("/Query /TN \"" + TaskName + "\" /FO LIST /V", out code);
            if (code != 0) return "Not scheduled";
            Match next = Regex.Match(output, @"Next Run Time:\s*(.+)");
            Match last = Regex.Match(output, @"Last Run Time:\s*(.+)");
            string s = "Scheduled";
            if (next.Success) s += " — next run " + next.Groups[1].Value.Trim();
            if (last.Success && !last.Groups[1].Value.Contains("1999") && !last.Groups[1].Value.Contains("N/A")) s += ", last run " + last.Groups[1].Value.Trim();
            return s;
        }
    }

    internal static class Mailer
    {
        public static void Send(AppSettings s, string subject, string html, string text, string attachmentPath, string pickupDirectory)
        {
            ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072; // TLS 1.2 on .NET 4.5 / Server 2012 R2
            using (var msg = new MailMessage())
            {
                msg.From = new MailAddress(s.FromAddress.Trim(), string.IsNullOrWhiteSpace(s.FromName) ? null : s.FromName.Trim());
                msg.To.Add(new MailAddress(s.ToAddress.Trim()));
                msg.Subject = subject;
                msg.SubjectEncoding = Encoding.UTF8;
                msg.BodyEncoding = Encoding.UTF8;
                msg.AlternateViews.Add(AlternateView.CreateAlternateViewFromString(text, Encoding.UTF8, "text/plain"));
                msg.AlternateViews.Add(AlternateView.CreateAlternateViewFromString(html, Encoding.UTF8, "text/html"));
                if (!string.IsNullOrEmpty(attachmentPath))
                    msg.Attachments.Add(new Attachment(attachmentPath, "application/pdf") { Name = Path.GetFileName(attachmentPath) });
                using (var client = new SmtpClient())
                {
                    client.Timeout = 120000;
                    if (!string.IsNullOrEmpty(pickupDirectory))
                    {
                        Directory.CreateDirectory(pickupDirectory);
                        client.DeliveryMethod = SmtpDeliveryMethod.SpecifiedPickupDirectory;
                        client.PickupDirectoryLocation = pickupDirectory;
                    }
                    else
                    {
                        client.Host = s.SmtpHost.Trim();
                        client.Port = s.SmtpPort;
                        client.EnableSsl = s.SmtpStartTls;
                        client.DeliveryMethod = SmtpDeliveryMethod.Network;
                        if (!string.IsNullOrWhiteSpace(s.SmtpUser))
                        {
                            client.UseDefaultCredentials = false;
                            client.Credentials = new NetworkCredential(s.SmtpUser.Trim(), s.SmtpPassword);
                        }
                    }
                    client.Send(msg);
                }
            }
        }
    }
}
