using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace PolarniteAudit
{
    /// <summary>
    /// Collector 1.14 rules: Windows 10/11 used as a server (power, auto sign-in, UAC, paused
    /// updates, Windows 11 readiness), installed-software support dates, Synology Active Backup
    /// and Drive Client, Veeam Backup &amp; Replication console data, and OneDrive per user.
    /// </summary>
    internal sealed partial class Analyzer
    {
        private void PlatformChecks()
        {
            ClientPlatform();
            SoftwareLifecycle();
            SynologyBackup();
            VeeamConsole();
            OneDrive();
        }

        private void Hint(string id, string text)
        {
            string current;
            a.AutoHints[id] = a.AutoHints.TryGetValue(id, out current) && current.Length > 0 ? current.TrimEnd() + " " + text : text;
        }

        private static string Duration(double seconds)
        {
            if (seconds >= 3600 && seconds % 3600 == 0) return J.Plural((int)(seconds / 3600), "hour", "hours");
            if (seconds >= 60) return J.Plural((int)Math.Round(seconds / 60), "minute", "minutes");
            return J.Plural((int)seconds, "second", "seconds");
        }

        private string AgeText(DateTime? d)
        {
            if (!d.HasValue) return "Never";
            int days = DaysSince(d);
            return days <= 0 ? "Today" : J.Plural(days, "day", "days") + " ago";
        }

        /// <summary>Adds a block to Backups before the closing "Local evidence only" note.</summary>
        private void BackupBlock(Block b)
        {
            Section sec = SectionNamed("Backups");
            int note = sec.Blocks.FindLastIndex(x => x is NoteBlock && ((NoteBlock)x).Text.StartsWith("Local evidence only", StringComparison.Ordinal));
            if (note >= 0) sec.Blocks.Insert(note, b); else sec.Blocks.Add(b);
        }

        private string Ago(DateTime? d)
        {
            if (!d.HasValue) return "never";
            int days = DaysSince(d);
            return J.FormatDateTime(d) + (days <= 0 ? " (today)" : " (" + J.Plural(days, "day", "days") + " ago)");
        }

        /// <summary>Best-effort timestamp and outcome of one backup log line (same rules as the collector).</summary>
        internal static void ClassifyLogLine(string text, out DateTime? time, out string outcome)
        {
            time = null;
            Match m = Regex.Match(text ?? "", @"(?<yr>20\d{2})[-/.](?<mo>\d{1,2})[-/.](?<dy>\d{1,2})[ T_]+(?<hh>\d{1,2}):(?<mi>\d{2})(?::(?<ss>\d{2}))?");
            if (m.Success)
            {
                try
                {
                    time = new DateTime(int.Parse(m.Groups["yr"].Value), int.Parse(m.Groups["mo"].Value), int.Parse(m.Groups["dy"].Value),
                        int.Parse(m.Groups["hh"].Value), int.Parse(m.Groups["mi"].Value), m.Groups["ss"].Success ? int.Parse(m.Groups["ss"].Value) : 0);
                }
                catch (ArgumentOutOfRangeException) { time = null; }
            }
            if (!time.HasValue)
            {
                Match sys = Regex.Match(text ?? "", @"^(?<mon>[A-Z][a-z]{2}) +(?<dy>\d{1,2}) (?<hms>\d{2}:\d{2}:\d{2})");
                DateTime parsed;
                if (sys.Success && DateTime.TryParseExact(sys.Groups["mon"].Value + " " + sys.Groups["dy"].Value + " " + DateTime.Now.Year + " " + sys.Groups["hms"].Value,
                        "MMM d yyyy HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.None, out parsed))
                    time = parsed > DateTime.Now.AddDays(2) ? parsed.AddYears(-1) : parsed;
            }
            string clean = Regex.Replace(text ?? "", @"(?i)\b(no|0|zero)\s+(errors?|failures?|warnings?)\b", "");
            if (Regex.IsMatch(clean, @"(?i)\b(fail(ed|ure|s)?|error|abort(ed)?|cancel(l)?ed|partial(ly)?\s+(complete|success))")) outcome = "Failure";
            else if (Regex.IsMatch(clean, @"(?i)\b(succe(ss|eded|ssful(ly)?)|completed?|finished)\b")) outcome = "Success";
            else outcome = "Other";
        }

        // ------------------------------------------------------------ Windows 10/11 and device settings

        private void ClientPlatform()
        {
            CheckResult c = C("ClientPlatform");
            object osr = C("OSRelease").First;
            string edition = J.Str(osr, "EditionID");
            if (a.IsClientOs)
            {
                Add("client-os", Severity.Info, "System", "Windows " + (a.OsName.Contains("11") ? "11" : "10") + " is used as a server",
                    "A Windows client OS allows at most 20 simultaneous inbound file-sharing connections, restarts for feature updates and is licensed as a workstation. Keep sleep off, schedule restarts, and plan a move to Windows Server if more people depend on it.");
                if (Regex.IsMatch(edition, "^Core", RegexOptions.IgnoreCase))
                    Add("home-edition", Severity.Warning, "System", "Windows Home edition",
                        "Home cannot join a domain and has no Group Policy, BitLocker management or Remote Desktop host. Upgrade to Pro (or Enterprise).");
            }
            if (!c.Ok || c.First == null) return;
            object p = c.First;
            var t = new TableBlock("Power, sign-in and update settings", new[] { "Setting", "Status", "Detail" }, new[] { 2.4, 1.6, 4.0 });
            var power = J.List(J.Get(p, "Power"));
            Func<string, double?> ac = name => J.Num(power.FirstOrDefault(x => J.Str(x, "Setting") == name), "AcSeconds");
            Match plan = Regex.Match(J.Str(p, "PowerScheme"), @"\(([^()]*(\([^()]*\))?[^()]*)\)\s*\*?\s*$");
            string planName = plan.Success ? "Power plan: " + plan.Groups[1].Value.Trim() : "";

            double? sleep = ac("SleepAfter");
            if (sleep.HasValue)
            {
                bool sleeps = sleep.Value > 0;
                t.Add("Sleep on AC power", new Cell(sleeps ? "After " + Duration(sleep.Value) : "Never", sleeps ? Severity.Critical : Severity.Pass), planName);
                if (sleeps)
                    Add("power-sleep", Severity.Critical, "System", "Computer goes to sleep after " + Duration(sleep.Value) + " idle",
                        "While asleep it serves no files, runs no backups and misses patching. Set sleep to Never on AC power (powercfg /change standby-timeout-ac 0) or in the RMM power policy.");
                else Add("power-sleep", Severity.Pass, "System", "Sleep is off on AC power", "");
            }
            double? hib = ac("HibernateAfter");
            bool hibernateOn = (J.Num(p, "HibernateEnabled") ?? 1) != 0;
            if (hib.HasValue && hibernateOn)
            {
                bool hibernates = hib.Value > 0;
                t.Add("Hibernate on AC power", new Cell(hibernates ? "After " + Duration(hib.Value) : "Never", hibernates ? Severity.Warning : Severity.Pass), "");
                if (hibernates)
                    Add("power-hibernate", Severity.Warning, "System", "Computer hibernates after " + Duration(hib.Value) + " idle", "Set hibernate to Never on AC power (powercfg /change hibernate-timeout-ac 0).");
            }
            if (a.IsClientOs && (J.Num(p, "FastStartup") ?? 0) == 1)
                t.Add("Fast startup", new Cell("On", Severity.Info), "Shut down is not a full restart; use Restart so updates and driver changes complete.");

            string autoLogon = J.Str(p, "AutoAdminLogon").Trim();
            bool storedPassword = J.Bool(p, "AutoLogonPasswordStored") == true;
            string autoUser = J.Str(p, "AutoLogonUser");
            if (autoLogon == "1")
            {
                t.Add("Automatic sign-in", new Cell("On", storedPassword ? Severity.Critical : Severity.Warning),
                    (autoUser.Length > 0 ? "Account " + autoUser : "On") + (storedPassword ? "; password stored in clear text in the registry" : ""));
                if (storedPassword)
                    Add("autologon-password", Severity.Critical, "Accounts", "Automatic sign-in stores a password in clear text",
                        "Account \"" + autoUser + "\" signs in automatically and its password is in the registry (Winlogon DefaultPassword), readable by any administrator or malware. Turn auto sign-in off; if software needs a signed-in user, run it as a service or use Sysinternals Autologon, which encrypts the password.");
                else
                    Add("autologon", Severity.Warning, "Accounts", "Automatic sign-in is on" + (autoUser.Length > 0 ? " (" + autoUser + ")" : ""),
                        "Anyone with physical or console access gets a signed-in session. Turn it off unless an application requires it, and lock the screen.");
            }
            else t.Add("Automatic sign-in", new Cell("Off", Severity.Pass), "");

            double? lua = J.Num(p, "UacEnabled");
            if (lua.HasValue)
            {
                t.Add("User Account Control", new Cell(lua.Value == 0 ? "Off" : "On", lua.Value == 0 ? Severity.Warning : Severity.Pass),
                    lua.Value != 0 && (J.Num(p, "UacAdminPrompt") ?? 5) == 0 ? "Administrators are elevated without a prompt" : "");
                if (lua.Value == 0)
                    Add("uac-off", Severity.Warning, "Security", "User Account Control is turned off", "Every administrator process runs fully elevated, so malware gets full rights at once. Set EnableLUA to 1 and restart.");
            }

            DateTime paused = DateTime.MinValue;
            foreach (string key in new[] { "UpdatesPausedUntil", "QualityUpdatesPausedUntil", "FeatureUpdatesPausedUntil" })
            {
                DateTime d;
                if (DateTime.TryParse(J.Str(p, key), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out d) && d.ToLocalTime() > paused)
                    paused = d.ToLocalTime();
            }
            if (paused > now)
            {
                t.Add("Windows Update", new Cell("Paused", Severity.Warning), "Until " + J.FormatDate(paused));
                Add("updates-paused", Severity.Warning, "Patching", "Windows Update is paused until " + J.FormatDate(paused), "Security updates are not installing. Resume updates in Settings > Windows Update or the RMM patch policy.");
            }
            string target = J.Str(p, "TargetReleaseVersion");
            double? deferFeature = J.Num(p, "DeferFeatureDays"), deferQuality = J.Num(p, "DeferQualityDays");
            var policy = new List<string>();
            if (target.Length > 0) policy.Add("pinned to " + target);
            if (deferFeature > 0) policy.Add("feature updates deferred " + deferFeature + " days");
            if (deferQuality > 0) policy.Add("quality updates deferred " + deferQuality + " days");
            if (policy.Count > 0) t.Add("Update policy", new Cell("Managed", Severity.Info), string.Join(", ", policy.ToArray()));
            if (deferQuality > 14)
                Add("updates-deferred", Severity.Warning, "Patching", "Security updates are deferred " + deferQuality + " days by policy", "Shorten the quality-update deferral to 7 days or less.");

            // Windows 10: is the hardware ready for Windows 11?
            if (a.IsClientOs && a.OsName.IndexOf("Windows 10", StringComparison.OrdinalIgnoreCase) >= 0 && !Regex.IsMatch(edition, "EnterpriseS", RegexOptions.IgnoreCase))
            {
                string spec = J.Str(p, "TpmSpecVersion");
                bool? secureBoot = J.Bool(C("SecureBoot").First, "Enabled");
                bool tpm2 = spec.StartsWith("2.", StringComparison.Ordinal);
                string detail = "TPM " + (spec.Length > 0 ? spec.Split(',')[0].Trim() : "not found") + ", Secure Boot " + (secureBoot == true ? "on" : secureBoot == false ? "off" : "unknown") + ".";
                if (tpm2 && secureBoot == true)
                    Add("win11-ready", Severity.Info, "Lifecycle", "Hardware has TPM 2.0 and Secure Boot for Windows 11", detail + " Check the processor against Microsoft's supported CPU list, then schedule the upgrade.");
                else if (spec.Length > 0 || secureBoot.HasValue)
                    Add("win11-ready", Severity.Warning, "Lifecycle", "Hardware may not meet Windows 11 requirements", detail + " Windows 11 needs TPM 2.0 and Secure Boot (UEFI). Plan a replacement or firmware change before Windows 10 coverage ends.");
            }
            if (t.Rows.Count > 0) SectionNamed("Device settings").Blocks.Add(t);
        }

        // ------------------------------------------------------------ installed software support dates

        private sealed class SoftwareRule
        {
            public Regex Pattern; public string Name; public Func<Match, DateTime?> End; public bool Exposed;
            public SoftwareRule(string pattern, string name, Func<Match, DateTime?> end, bool exposed)
            { Pattern = new Regex(pattern, RegexOptions.IgnoreCase); Name = name; End = end; Exposed = exposed; }
        }

        private static DateTime? Pick(string key, params object[] pairs)
        {
            for (int i = 0; i + 1 < pairs.Length; i += 2)
                if (string.Equals((string)pairs[i], key, StringComparison.OrdinalIgnoreCase)) return (DateTime)pairs[i + 1];
            return null;
        }

        private static readonly SoftwareRule[] SoftwareRules =
        {
            new SoftwareRule(@"^Microsoft Office (?!.*(Proofing|Interop|Language|MUI|Runtime|Click-to-Run|Access database engine|Web Components))[A-Za-z ]*\b(?<v>2010|2013|2016|2019|2021|2024)\b", "Microsoft Office",
                m => Pick(m.Groups["v"].Value, "2010", new DateTime(2020, 10, 13), "2013", new DateTime(2023, 4, 11), "2016", new DateTime(2025, 10, 14),
                    "2019", new DateTime(2025, 10, 14), "2021", new DateTime(2026, 10, 13), "2024", new DateTime(2029, 10, 9)), false),
            new SoftwareRule(@"^Microsoft Exchange Server (?<v>2010|2013|2016|2019)\b", "Microsoft Exchange Server",
                m => Pick(m.Groups["v"].Value, "2010", new DateTime(2020, 10, 13), "2013", new DateTime(2023, 4, 11), "2016", new DateTime(2025, 10, 14), "2019", new DateTime(2025, 10, 14)), true),
            new SoftwareRule(@"^Microsoft SQL Server (?<v>2008 R2|2008|2012|2014|2016|2017|2019) \((32|64)-bit\)$", "Microsoft SQL Server",
                m => Pick(m.Groups["v"].Value, "2008 R2", new DateTime(2019, 7, 9), "2008", new DateTime(2019, 7, 9), "2012", new DateTime(2022, 7, 12),
                    "2014", new DateTime(2024, 7, 9), "2016", new DateTime(2026, 7, 14), "2017", new DateTime(2027, 10, 12), "2019", new DateTime(2030, 1, 8)), false),
            new SoftwareRule(@"^Microsoft SharePoint (Server|Foundation) (?<v>2010|2013|2016|2019)\b", "Microsoft SharePoint",
                m => Pick(m.Groups["v"].Value, "2010", new DateTime(2021, 4, 13), "2013", new DateTime(2023, 4, 11), "2016", new DateTime(2026, 7, 14), "2019", new DateTime(2026, 7, 14)), true),
            new SoftwareRule(@"^Adobe (Acrobat|Reader) (?<v>XI|X|2015|2017|2020)\b", "Adobe Acrobat / Reader",
                m => Pick(m.Groups["v"].Value, "X", new DateTime(2015, 11, 15), "XI", new DateTime(2017, 10, 15), "2015", new DateTime(2020, 4, 7),
                    "2017", new DateTime(2022, 6, 6), "2020", new DateTime(2025, 11, 30)), false),
            new SoftwareRule(@"^Java(\(TM\))? ?(?<v>6|7)\b", "Java", m => m.Groups["v"].Value == "6" ? new DateTime(2018, 12, 31) : new DateTime(2022, 7, 19), false),
            new SoftwareRule(@"^Python 2\.\d", "Python 2", m => new DateTime(2020, 1, 1), false),
            new SoftwareRule(@"^QuickBooks\b.*?\b(?<v>20\d\d)\b", "QuickBooks Desktop",
                m => new DateTime(int.Parse(m.Groups["v"].Value, CultureInfo.InvariantCulture) + 3, 5, 31), false),
            new SoftwareRule(@"^QuickBooks Enterprise Solutions\b.*?\b(?<v>\d{2})\.0\b", "QuickBooks Enterprise",
                m => new DateTime(2000 + int.Parse(m.Groups["v"].Value, CultureInfo.InvariantCulture) + 3, 5, 31), false),
        };

        private void SoftwareLifecycle()
        {
            CheckResult c = C("Software");
            if (!c.Ok) return;
            var table = new TableBlock("Installed software past or near end of support", new[] { "Software", "Support ends", "Status" }, new[] { 4.6, 1.5, 1.6 });
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (object s in c.Data)
            {
                string name = J.Str(s, "DisplayName").Trim();
                if (name.Length == 0 || !seen.Add(name)) continue;
                foreach (SoftwareRule rule in SoftwareRules)
                {
                    Match m = rule.Pattern.Match(name);
                    if (!m.Success) continue;
                    DateTime? end = rule.End(m);
                    if (!end.HasValue) break;
                    int days = (int)Math.Floor((end.Value - now.Date).TotalDays);
                    if (days > 365) break;
                    bool past = days < 0;
                    Severity sev = past ? (rule.Exposed ? Severity.Critical : Severity.Warning) : Severity.Info;
                    table.Add(name, J.FormatDate(end), new Cell(past ? "Unsupported" : "Ends in " + days + " days", past ? sev : Severity.Warning));
                    if (past)
                        Add("eol-" + name, sev, "Lifecycle", name + " is out of support",
                            "Support ended " + J.FormatDate(end) + "; it no longer receives security fixes." + (rule.Exposed ? " It is usually reachable from the network or internet, so replace it first." : " Plan an upgrade or removal."));
                    else
                        Add("eol-" + name, Severity.Info, "Lifecycle", name + " support ends " + J.FormatDate(end), "Plan the upgrade before support ends.");
                    break;
                }
            }
            if (table.Rows.Count > 0) SectionNamed("Software support").Blocks.Add(table);
        }

        // ------------------------------------------------------------ Synology

        private void SynologyBackup()
        {
            CheckResult abb = C("SynologyActiveBackup");
            object sum = abb.Data.FirstOrDefault(d => J.Str(d, "RecordType") == "Summary");
            if (abb.Ok && sum != null && J.Bool(sum, "Installed") == true) ActiveBackup(abb, sum);

            // Synology Drive Client (per-user file backup and sync).
            object inv = C("SynologyDriveInventory").First;
            var roots = J.List(J.Get(inv, "Roots")).Where(r => J.Str(r, "Status") == "Present").ToList();
            if (roots.Count == 0) return;
            var procs = J.List(J.Get(inv, "Processes"));
            bool driveRunning = procs.Count > 0;
            var driveLines = C("SynologyDriveDetails").Data.SelectMany(d => J.List(J.Get(d, "Lines"))).ToList();
            DateTime? driveOk = null, driveBad = null; string badText = "";
            foreach (object l in driveLines)
            {
                DateTime? time; string outcome;
                ClassifyLogLine(J.Str(l, "Text"), out time, out outcome);
                if (!time.HasValue) continue;
                if (outcome == "Success" && (!driveOk.HasValue || time > driveOk)) driveOk = time;
                if (outcome == "Failure" && (!driveBad.HasValue || time > driveBad)) { driveBad = time; badText = J.Str(l, "Text"); }
            }
            var dt = new TableBlock("Synology Drive Client", new[] { "Item", "Status", "Detail" }, new[] { 2.2, 1.5, 4.3 });
            dt.Add("Client", new Cell(driveRunning ? "Running" : "Not running", driveRunning ? Severity.Pass : Severity.Warning),
                "Set up for " + J.Plural(roots.Count, "user profile", "user profiles") + (driveRunning ? "" : "; nobody is signed in or the client is closed"));
            if (driveOk.HasValue) dt.Add("Last success", new Cell(AgeText(driveOk), DaysSince(driveOk) > 2 ? Severity.Warning : Severity.Pass), J.FormatDateTime(driveOk) + " (from the client log)");
            if (driveBad.HasValue) dt.Add("Last error", new Cell(AgeText(driveBad), (!driveOk.HasValue || driveBad > driveOk) ? Severity.Warning : Severity.Info), J.Shorten(badText, 140));
            BackupBlock(dt);
            if (!driveRunning)
                Add("drive-not-running", Severity.Warning, "Backups", "Synology Drive Client is not running",
                    "Drive Client backup and sync tasks run only while the user is signed in and the client is open. If this computer relies on it, use Active Backup for Business (runs as a service) instead.");
            if (driveBad.HasValue && (!driveOk.HasValue || driveBad > driveOk) && DaysSince(driveBad) <= 7)
                Add("drive-errors", Severity.Warning, "Backups", "Synology Drive Client logged errors after its last success", J.Shorten(badText, 200));
            Hint("backup_last_success", "Synology Drive Client " + (driveRunning ? "running" : "not running") + (driveOk.HasValue ? ", last success in log " + J.FormatDateTime(driveOk) : "") + ".");
        }

        private string abbLine;          // for the backup manual checks
        private bool abbHealthy = true, abbFailureOpen;

        /// <summary>
        /// Active Backup for Business agent: backup runs are read from backup-job.cpp lines
        /// ("Prepare snapshot job" ... "in backup routine, has_fail_volume 'N'"). The expected
        /// interval comes from the gaps between past successes, so weekly schedules are not flagged.
        /// </summary>
        private void ActiveBackup(CheckResult abb, object sum)
        {
            var t = new TableBlock("Synology Active Backup for Business (agent on this computer)", new[] { "Item", "Status", "Detail" }, new[] { 2.2, 1.5, 4.3 });
            var services = J.List(J.Get(sum, "Services"));
            bool running = services.Any(s => J.Str(s, "State") == "Running");
            if (services.Count > 0)
                t.Add("Agent service", new Cell(running ? "Running" : "Stopped", running ? Severity.Pass : Severity.Critical), string.Join(", ", services.Select(s => J.Str(s, "DisplayName")).ToArray()));

            var events = abb.Data.Where(d => J.Str(d, "RecordType") == "Event" && J.Date(d, "Time").HasValue).ToList();
            Func<string, List<DateTime>> times = kind => events.Where(e => J.Str(e, "Kind") == kind).Select(e => J.Date(e, "Time").Value).OrderBy(x => x).ToList();
            var ok = times("Success");
            var failed = events.Where(e => J.Str(e, "Kind") == "FailedVolumes").OrderBy(e => J.Date(e, "Time")).ToList();
            var starts = times("Start");
            var errors = events.Where(e => J.Str(e, "Kind") == "BackupError").OrderBy(e => J.Date(e, "Time")).ToList();
            DateTime? lastOk = ok.Count > 0 ? ok[ok.Count - 1] : (DateTime?)null;
            DateTime? lastFail = failed.Count > 0 ? J.Date(failed[failed.Count - 1], "Time") : null;
            DateTime? lastStart = starts.Count > 0 ? starts[starts.Count - 1] : (DateTime?)null;
            DateTime? lastErr = errors.Count > 0 ? J.Date(errors[errors.Count - 1], "Time") : null;
            DateTime? oldest = J.Date(sum, "OldestLogTime"), newestLog = J.Date(sum, "NewestLogTime");

            // Usual interval between successful backups (median gap between distinct days).
            var days = ok.Select(x => x.Date).Distinct().ToList();
            var gaps = new List<double>();
            for (int i = 1; i < days.Count; i++) gaps.Add((days[i] - days[i - 1]).TotalDays);
            gaps.Sort();
            double usual = gaps.Count > 0 ? gaps[gaps.Count / 2] : 0;
            double allowed = gaps.Count > 0 ? Math.Max(2, usual * 1.5 + 1) : 8;
            string cadence = usual >= 1 ? "usually every " + (usual == 1 ? "day" : usual == 7 ? "week" : Math.Round(usual) + " days") : "";

            var connDays = abb.Data.Where(d => J.Str(d, "RecordType") == "ConnectionErrors" && DaysSince(J.Date(d, "Day")) <= 7 && (J.Num(d, "Count") ?? 0) > 0)
                .Select(d => J.Date(d, "Day").Value).OrderBy(x => x).ToList();
            int connErrors = connDays.Count;
            var conns = J.List(J.Get(sum, "NasConnections")).Select(x => J.Str(x, "RemoteAddress")).Where(x => x.Length > 0).Distinct().ToList();

            bool failOpen = lastFail.HasValue && (!lastOk.HasValue || lastFail > lastOk);
            int age = DaysSince(lastOk);
            t.Add("Last successful backup", new Cell(AgeText(lastOk), !lastOk.HasValue || age > allowed ? Severity.Critical : Severity.Pass),
                lastOk.HasValue ? J.FormatDateTime(lastOk) + (cadence.Length > 0 ? " (" + cadence + ")" : "") : "None in the agent logs" + (oldest.HasValue ? " since " + J.FormatDate(oldest) : ""));
            if (lastFail.HasValue)
                t.Add("Last failed backup", new Cell(AgeText(lastFail), failOpen ? Severity.Critical : Severity.Info), J.Shorten(J.Str(failed[failed.Count - 1], "Text"), 140));
            if (lastStart.HasValue && (!lastOk.HasValue || lastStart > lastOk))
                t.Add("Backup in progress or stopped", new Cell(AgeText(lastStart), DaysSince(lastStart) >= 1 ? Severity.Warning : Severity.Info), "Started " + J.FormatDateTime(lastStart) + " with no finish line yet");
            t.Add("Successful backups in logs", J.Plural(ok.Count, "run", "runs"), oldest.HasValue ? "Logs cover " + J.FormatDate(oldest) + " to " + J.FormatDate(newestLog) : "");
            t.Add("NAS connection", new Cell(conns.Count > 0 ? "Connected" : connErrors > 0 ? "Errors" : "Idle", conns.Count > 0 ? Severity.Pass : connErrors > 0 ? Severity.Warning : Severity.Info),
                (conns.Count > 0 ? string.Join(", ", conns.ToArray()) + " on port 5510. " : "") + (connErrors > 0 ? "Could not reach the NAS on " + string.Join(", ", connDays.Select(x => x.ToString("d MMM", CultureInfo.InvariantCulture)).ToArray()) + "." : ""));
            BackupBlock(t);

            var summary = new List<string>();
            if (failOpen)
            {
                Add("abb-failed", Severity.Critical, "Backups", "Synology Active Backup: the last backup failed",
                    "Run at " + J.FormatDateTime(lastFail) + " reported failed volumes" + (lastOk.HasValue ? "; last success " + J.FormatDateTime(lastOk) : "") + ". Check the task log in Active Backup for Business on the NAS.");
                summary.Add("last run " + J.FormatDateTime(lastFail) + " failed");
            }
            else if (!lastOk.HasValue)
            {
                bool longEnough = oldest.HasValue && DaysSince(oldest) >= allowed;
                Add("abb-none", longEnough ? Severity.Critical : Severity.Warning, "Backups", "Synology Active Backup: no successful backup in the agent logs",
                    (oldest.HasValue ? "The logs go back to " + J.FormatDate(oldest) + ". " : "") + "Check the device and its schedule in Active Backup for Business on the NAS.");
                summary.Add("no successful run in the agent logs");
            }
            else if (age > allowed)
            {
                Add("abb-age", Severity.Critical, "Backups", "Synology Active Backup: no successful backup in " + age + " days",
                    "Last success " + J.FormatDateTime(lastOk) + (cadence.Length > 0 ? "; it normally runs " + cadence.Replace("usually ", "") : "") + ". Check the task and NAS connection in Active Backup for Business.");
                summary.Add("last success " + J.FormatDateTime(lastOk) + " (" + age + " days ago)");
            }
            else
            {
                Add("abb-ok", Severity.Pass, "Backups", "Synology Active Backup succeeded " + J.FormatDateTime(lastOk) + (cadence.Length > 0 ? " (" + cadence + ")" : ""), "");
                summary.Add("last success " + J.FormatDateTime(lastOk) + (cadence.Length > 0 ? ", " + cadence : ""));
            }
            if (lastStart.HasValue && (!lastOk.HasValue || lastStart > lastOk) && !failOpen && DaysSince(lastStart) >= 1)
                Add("abb-unfinished", Severity.Warning, "Backups", "Synology Active Backup: the run started " + J.FormatDateTime(lastStart) + " never finished",
                    "No finish line followed it in the agent log. It may have been cancelled or lost its NAS connection.");
            if (lastErr.HasValue && lastOk.HasValue && lastErr > lastOk && !failOpen)
                Add("abb-errors", Severity.Warning, "Backups", "Synology Active Backup logged errors after its last success", J.Shorten(J.Str(errors[errors.Count - 1], "Text"), 200));
            if (connErrors > 0)
                Add("abb-connection", Severity.Warning, "Backups", "Synology Active Backup agent could not reach the NAS on " + J.Plural(connErrors, "day", "days") + " this week",
                    string.Join(", ", connDays.Select(x => x.ToString("d MMM", CultureInfo.InvariantCulture)).ToArray()) + ". Usually a NAS restart, update or network outage; backups that were due then may have been delayed.");

            // Errors inside runs that still finished (for example VSS BackupComplete failing every week).
            int runsWithErrors = 0; object runError = null;
            foreach (DateTime done in ok.Skip(Math.Max(0, ok.Count - 4)))
            {
                DateTime begin = starts.Where(x => x <= done && x > done.AddDays(-1)).DefaultIfEmpty(done.AddHours(-6)).Max();
                object err = errors.LastOrDefault(e => J.Date(e, "Time") >= begin && J.Date(e, "Time") <= done);
                if (err != null) { runsWithErrors++; runError = err; }
            }
            if (runsWithErrors >= 2)
                Add("abb-run-errors", Severity.Warning, "Backups", "Synology Active Backup logs an error during each run",
                    runsWithErrors + " of the last " + Math.Min(4, ok.Count) + " runs finished but logged: " + J.Shorten(J.Str(runError, "Text"), 160) +
                    (J.Str(runError, "Text").IndexOf("BackupComplete", StringComparison.OrdinalIgnoreCase) >= 0 ? " VSS writers are not told the backup completed, so SQL or Exchange logs may not truncate. Check vssadmin list writers." : ""));

            abbHealthy = !failOpen && lastOk.HasValue && age <= allowed;
            abbFailureOpen = failOpen;
            abbLine = "Synology Active Backup " + string.Join(", ", summary.ToArray()) + " (agent log)";
        }

        // ------------------------------------------------------------ Veeam Backup & Replication console

        private void VeeamConsole()
        {
            CheckResult c = C("VeeamServerJobs");
            if (!c.Ok) return;
            var jobs = c.Data.Where(d => J.Str(d, "RecordType") == "Job").ToList();
            var table = new TableBlock("Veeam Backup & Replication jobs (console)", new[] { "Job", "Type", "Schedule", "Last result", "Last run", "Restore points" }, new[] { 2.4, 1.3, 1.0, 1.1, 1.5, 1.5 });
            var copies = new List<string>();
            foreach (object j in jobs)
            {
                string name = J.Str(j, "Name"), type = J.Str(j, "TypeText"), jobType = J.Str(j, "JobType"), result = J.Str(j, "LastResult");
                if (type.Length == 0) type = jobType;
                bool copy = Regex.IsMatch(jobType + " " + type, "BackupSync|Copy", RegexOptions.IgnoreCase);
                bool manual = J.Bool(j, "RunManually") == true;
                bool enabled = J.Bool(j, "ScheduleEnabled") == true && !manual;
                DateTime? lastEnd = J.Date(j, "LastEnd"), newest = J.Date(j, "NewestRestorePoint");
                if (lastEnd.HasValue && lastEnd.Value.Year < 2000) lastEnd = null;
                Severity sev = result == "Failed" ? Severity.Critical : result == "Warning" ? Severity.Warning : result == "Success" ? Severity.Pass : Severity.Unknown;
                double? points = J.Num(j, "RestorePoints");
                table.Add(name, type, new Cell(manual ? "Manual" : enabled ? "Scheduled" : "Disabled", manual ? Severity.Info : enabled ? Severity.Pass : Severity.Warning), new Cell(result.Length > 0 ? result : "—", sev),
                    J.FormatDateTime(lastEnd), points.HasValue ? points.Value + (newest.HasValue ? ", newest " + J.FormatDate(newest) : "") : "");
                if (copy) copies.Add(name + (result.Length > 0 ? " (" + result.ToLowerInvariant() + ")" : ""));
                if (Regex.IsMatch(J.Str(j, "Repository"), "cloud|wasabi|s3|azure|offsite|b2|backblaze|immutable|hardened", RegexOptions.IgnoreCase))
                    copies.Add(name + " to repository " + J.Str(j, "Repository"));

                if (copy && J.Bool(j, "ScheduleEnabled") == true && newest.HasValue && DaysSince(newest) > 7)
                    Add("veeam-copy-age-" + name, Severity.Warning, "Backups", "Veeam backup copy \"" + name + "\" has no copy newer than " + DaysSince(newest) + " days",
                        "Newest copy " + J.FormatDateTime(newest) + ". Expected if its source job only runs manually; otherwise the copy has stopped. Check the job in the Veeam console.");
                if (!enabled && !copy && !manual)
                    Add("veeam-disabled-" + name, Severity.Warning, "Backups", "Veeam job \"" + name + "\" is not scheduled", "The job's schedule is disabled, so it only runs manually.");
                if (manual || veeamJobs.Any(v => string.Equals(v.Job, name, StringComparison.OrdinalIgnoreCase))) continue; // manual, or already judged from event 190
                if (result != "Success" && result != "Warning" && result != "Failed") continue;
                DateTime? lastSuccess = result == "Success" ? (lastEnd ?? newest) : newest;
                veeamJobs.Add(new JobSummary { Product = "Veeam B&R", Job = name, LastResult = result, LastRun = lastEnd, LastSuccess = lastSuccess, Runs = 1, Failed = result == "Failed" ? 1 : 0 });
                if (result == "Failed")
                    Add("veeam-" + name, Severity.Critical, "Backups", "Veeam job \"" + name + "\" failed on its last run", "Last run " + J.FormatDateTime(lastEnd) + (newest.HasValue ? "; newest restore point " + J.FormatDateTime(newest) : "") + ".");
                else if (enabled && !copy && lastSuccess.HasValue && DaysSince(lastSuccess) > 2)
                    Add("veeam-age-" + name, Severity.Critical, "Backups", "Veeam job \"" + name + "\" has no restore point newer than " + DaysSince(lastSuccess) + " days", "Newest restore point " + J.FormatDateTime(lastSuccess) + ".");
                else if (result == "Warning")
                    Add("veeam-warn-" + name, Severity.Warning, "Backups", "Veeam job \"" + name + "\" finished with warnings", "Last run " + J.FormatDateTime(lastEnd) + ". Review the session in the console.");
            }
            if (table.Rows.Count > 0) BackupBlock(table);
            if (copies.Count > 0) Hint("backup_offsite", "Veeam offsite/copy evidence: " + string.Join("; ", copies.Distinct().Take(5).ToArray()) + ".");

            var repoTable = new TableBlock("Veeam repositories", new[] { "Repository", "Free", "Size" }, new[] { 4.2, 1.8, 1.6 });
            foreach (object repo in c.Data.Where(d => J.Str(d, "RecordType") == "Repository"))
            {
                double? total = J.Num(repo, "TotalGB"), free = J.Num(repo, "FreeGB");
                if (!total.HasValue || !free.HasValue || total.Value <= 0) continue;
                double pct = free.Value / total.Value * 100;
                Severity sev = pct < 5 ? Severity.Critical : pct < 15 ? Severity.Warning : Severity.Pass;
                string name = J.Str(repo, "Name");
                repoTable.Add(name, new Cell(Gb(free) + " (" + Math.Round(pct) + "%)", sev), Gb(total));
                if (sev != Severity.Pass)
                    Add("veeam-repo-" + name, sev, "Backups", "Veeam repository \"" + name + "\" has " + Math.Round(pct) + "% free", Gb(free) + " of " + Gb(total) + " free. Jobs fail when the repository fills; extend it or adjust retention.");
            }
            if (repoTable.Rows.Count > 0) BackupBlock(repoTable);

            object lic = c.Data.FirstOrDefault(d => J.Str(d, "RecordType") == "License");
            if (lic != null)
            {
                DateTime? exp = J.Date(lic, "ExpirationDate"), support = J.Date(lic, "SupportExpirationDate");
                int days = exp.HasValue ? (int)Math.Floor((exp.Value - now).TotalDays) : int.MaxValue;
                if (exp.HasValue && days < 0) Add("veeam-license", Severity.Critical, "Backups", "Veeam licence expired " + J.FormatDate(exp), "Jobs stop running when the licence expires. Renew it in the Veeam portal.");
                else if (exp.HasValue && days <= 60) Add("veeam-license", Severity.Warning, "Backups", "Veeam licence expires in " + J.Plural(days, "day", "days"), "Expires " + J.FormatDate(exp) + ". Renew it before jobs stop.");
                if (support.HasValue && support.Value < now) Add("veeam-support", Severity.Warning, "Backups", "Veeam support contract expired " + J.FormatDate(support), "Without support the server cannot be updated to new Veeam releases.");
            }
        }

        // ------------------------------------------------------------ OneDrive

        private void OneDrive()
        {
            var activity = C("OneDriveActivity").Data.Where(d => J.Get(d, "SID") != null).ToList();
            var config = C("OneDriveConfiguration").Data.Where(d => J.Str(d, "RecordType") == "Profile").ToList();
            if (activity.Count == 0) return;
            var table = new TableBlock("OneDrive (per user)", new[] { "User", "Account", "Folders in OneDrive", "Last activity", "User signed in" }, new[] { 1.6, 1.0, 2.4, 1.5, 1.5 });
            int kfmUsers = 0;
            foreach (object p in activity)
            {
                string sid = J.Str(p, "SID");
                string user = System.IO.Path.GetFileName(J.Str(p, "ProfilePath").TrimEnd('\\'));
                object cfg = config.FirstOrDefault(x => J.Str(x, "SID") == sid);
                bool hiveLoaded = cfg != null && J.Str(cfg, "Status") == "Collected";
                var slots = hiveLoaded ? new HashSet<string>(J.List(J.Get(cfg, "Accounts")).Select(x => J.Str(x, "AccountSlot")), StringComparer.OrdinalIgnoreCase) : null;
                var kfm = hiveLoaded ? J.List(J.Get(cfg, "KnownFolders")).Where(f => J.Str(f, "Assessment") == "PathUnderConfiguredOneDriveRoot")
                    .Select(f => J.Str(f, "Folder") == "Personal" ? "Documents" : J.Str(f, "Folder") == "My Pictures" ? "Pictures" : J.Str(f, "Folder")).ToList() : null;
                DateTime? lastUse = J.Date(p, "LastUseTime");
                foreach (object acct in J.List(J.Get(p, "Accounts")))
                {
                    string slot = J.Str(acct, "Account");
                    if (slots != null && !slots.Contains(slot)) continue; // signed out of this account
                    DateTime? lastWrite = J.Date(acct, "LastLogWrite");
                    bool business = slot.StartsWith("Business", StringComparison.OrdinalIgnoreCase);
                    int idle = DaysSince(lastWrite);
                    bool userActive = lastUse.HasValue && DaysSince(lastUse) <= 7;
                    Severity sev = idle > 14 && userActive ? Severity.Warning : idle > 14 ? Severity.Info : Severity.Pass;
                    string folders = kfm == null ? "Unknown (user not signed in)" : kfm.Count == 0 ? "None" : string.Join(", ", kfm.ToArray());
                    if (kfm != null && kfm.Count > 0) kfmUsers++;
                    table.Add(user, business ? "Work" : "Personal", folders, new Cell(AgeText(lastWrite), sev), J.FormatDate(lastUse));
                    if (sev == Severity.Warning)
                        Add("onedrive-idle-" + user, Severity.Warning, "Backups", "OneDrive for " + user + " has not synced in " + idle + " days",
                            user + " signed in " + J.FormatDate(lastUse) + " but OneDrive's activity stopped " + J.FormatDate(lastWrite) + ". Check the OneDrive icon for errors or a sign-in prompt.");
                    if (business && kfm != null && kfm.Count == 0)
                        Add("onedrive-kfm-" + user, Severity.Info, "Backups", "OneDrive folder backup is off for " + user,
                            "Desktop and Documents are stored only on this computer. Turn on OneDrive folder backup (Known Folder Move) by policy if this user's files matter.");
                }
            }
            if (table.Rows.Count == 0) return;
            BackupBlock(table);
            BackupBlock(new NoteBlock("OneDrive is sync, not backup: deletions and ransomware-encrypted files sync to the cloud too. Version history and the recycle bin (up to 93 days) help, but keep a separate backup for anything important. OneDrive runs only while the user is signed in."));
            if (kfmUsers > 0) Hint("backup_offsite", "OneDrive syncs known folders for " + J.Plural(kfmUsers, "user", "users") + " (sync, not a backup).");
        }
    }
}
