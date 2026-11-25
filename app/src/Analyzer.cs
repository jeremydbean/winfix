using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace WinFixAudit
{
    /// <summary>
    /// Turns collector evidence into findings and report sections. Rules are
    /// deliberately conservative: a check that was not collected never counts as
    /// a pass, it is listed under collection coverage instead.
    /// </summary>
    internal sealed class Analyzer
    {
        private readonly AuditReport r;
        private readonly AuditAnalysis a = new AuditAnalysis();
        private readonly string[] expectedAgents;
        private readonly DateTime now;

        private Analyzer(AuditReport report, string[] expectedAgents)
        {
            r = report;
            this.expectedAgents = expectedAgents ?? new string[0];
            now = report.AuditTime;
        }

        public static AuditAnalysis Run(AuditReport report, string[] expectedAgents)
        {
            var an = new Analyzer(report, expectedAgents);
            an.a.AuditTime = report.AuditTime;
            an.a.Elevated = report.Elevated;
            an.a.Incomplete = report.Incomplete;
            an.a.CollectorVersion = report.SchemaVersion;
            an.SystemInfo();
            an.CollectionHealth();
            an.Lifecycle();
            an.Patching();
            an.Security();
            an.Storage();
            an.Backups();
            an.Accounts();
            an.Events();
            an.Coverage();
            an.a.Findings.Sort((x, y) =>
            {
                int c = ((int)x.Severity).CompareTo((int)y.Severity);
                return c != 0 ? c : string.Compare(x.Area, y.Area, StringComparison.Ordinal);
            });
            return an.a;
        }

        // ---------------------------------------------------------------- helpers

        private Finding Add(string key, Severity sev, string area, string title, string detail)
        {
            var f = new Finding { Key = key, Severity = sev, Area = area, Title = title, Detail = detail ?? "" };
            a.Findings.Add(f);
            return f;
        }

        private CheckResult C(string name) { return r.Check(name); }

        private static bool Match(string text, string pattern)
        {
            return text != null && Regex.IsMatch(text, pattern, RegexOptions.IgnoreCase);
        }

        private static string Gb(double? v) { return v.HasValue ? v.Value.ToString("0.#", CultureInfo.InvariantCulture) + " GB" : "?"; }

        private int DaysSince(DateTime? d) { return d.HasValue ? (int)Math.Floor((now - d.Value).TotalDays) : -1; }

        private static Severity HealthSeverity(object v)
        {
            string s = J.Str(v).Trim();
            double? n = J.Num(v);
            if (s == "Healthy" || (n.HasValue && n.Value == 0 && !(v is string))) return Severity.Pass;
            if (s == "Warning" || (n.HasValue && n.Value == 1 && !(v is string))) return Severity.Warning;
            if (s == "Unhealthy" || (n.HasValue && n.Value == 2 && !(v is string))) return Severity.Critical;
            return Severity.Unknown;
        }

        private static string HealthText(object v)
        {
            switch (HealthSeverity(v))
            {
                case Severity.Pass: return "Healthy";
                case Severity.Warning: return "Warning";
                case Severity.Critical: return "Unhealthy";
                default: { string s = J.Str(v); return s.Length > 0 ? s : "Unknown"; }
            }
        }

        // ---------------------------------------------------------------- system

        private void SystemInfo()
        {
            object sys = C("System").First;
            a.ServerName = J.Str(sys, "ComputerName");
            if (a.ServerName.Length == 0)
            {
                Match m = Regex.Match(System.IO.Path.GetFileName(r.Path), @"^WinFixAudit-(.+)-\d{8}-\d{6}");
                a.ServerName = m.Success ? m.Groups[1].Value : "Unknown server";
            }
            a.DomainName = J.Str(sys, "Domain");
            a.PartOfDomain = J.Bool(sys, "PartOfDomain") ?? false;
            int role = (int)(J.Num(sys, "DomainRole") ?? -1);
            a.IsDomainController = role >= 4;
            string manufacturer = J.Str(sys, "Manufacturer"), model = J.Str(sys, "Model");
            a.IsVirtual = Match(manufacturer + " " + model, "VMware|Virtual|Hyper-V|QEMU|KVM|Xen|Amazon|Google|Nutanix|Parallels|OpenStack");

            object osr = C("OSRelease").First;
            string caption = J.Str(sys, "OS");
            if (caption.Length == 0) caption = J.Str(osr, "ProductName");
            string build = J.Str(sys, "Build");
            if (build.Length == 0) build = J.Str(osr, "CurrentBuild");
            string ubr = J.Str(osr, "UBR");
            string displayVersion = J.Str(osr, "DisplayVersion");
            a.OsName = caption;

            a.Snapshot.Add("Server", a.ServerName);
            a.Snapshot.Add("Operating system", caption + (displayVersion.Length > 0 ? " (" + displayVersion + ")" : ""));
            a.Snapshot.Add("Build", build + (ubr.Length > 0 ? "." + ubr : ""));
            string[] roles = { "Standalone workstation", "Member workstation", "Standalone server", "Member server", "Domain controller (backup)", "Domain controller (primary)" };
            string roleText = role >= 0 && role < roles.Length ? roles[role] : "";
            a.Snapshot.Add("Domain", a.PartOfDomain ? a.DomainName + (roleText.Length > 0 ? " — " + roleText : "") : "Workgroup (" + a.DomainName + ")");

            object reg = J.Get(C("DeviceRegistration").First, "Fields");
            a.EntraTenant = J.Str(reg, "TenantName");
            if (a.EntraTenant.Length > 0) a.Snapshot.Add("Entra tenant", a.EntraTenant);

            string hw = (manufacturer + " " + model).Trim();
            if (a.IsVirtual) hw += " (virtual machine)";
            a.Snapshot.Add("Hardware", hw);

            var cpus = C("Hardware").Data.Where(d => J.Get(d, "NumberOfCores") != null).ToList();
            if (cpus.Count > 0)
            {
                string cpuName = Regex.Replace(J.Str(cpus[0], "Name"), @"\s+", " ").Trim();
                double cores = cpus.Sum(c => J.Num(c, "NumberOfCores") ?? 0);
                double threads = cpus.Sum(c => J.Num(c, "NumberOfLogicalProcessors") ?? 0);
                a.Snapshot.Add("Processor", (cpus.Count > 1 ? cpus.Count + " × " : "") + cpuName + " — " + cores + " cores / " + threads + " threads");
            }
            double? mem = J.Num(sys, "MemoryGB");
            if (mem.HasValue) a.Snapshot.Add("Memory", Gb(mem));

            var bios = C("Hardware").Data.FirstOrDefault(d => J.Get(d, "SMBIOSBIOSVersion") != null);
            object ident = C("MachineIdentity").Data.FirstOrDefault(d => J.Get(d, "SerialNumber") != null);
            string serial = J.Str(ident, "SerialNumber");
            if (bios != null) a.Snapshot.Add("BIOS", J.Str(bios, "SMBIOSBIOSVersion") + (serial.Length > 0 && !a.IsVirtual ? " — serial " + serial : ""));

            DateTime? boot = J.Date(sys, "LastBoot");
            double? up = J.Num(sys, "UptimeDays");
            if (boot.HasValue) a.Snapshot.Add("Last restart", J.FormatDateTime(boot) + (up.HasValue ? " (" + Math.Round(up.Value, 1).ToString(CultureInfo.InvariantCulture) + " days ago)" : ""));
            DateTime? installed = J.Date(sys, "InstallDate");
            if (installed.HasValue) a.Snapshot.Add("OS installed", J.FormatDate(installed));

            var ips = new List<string>();
            foreach (object nic in C("Network").Data)
                foreach (object ip in J.List(J.Get(nic, "IPAddress")))
                {
                    string s = J.Str(ip);
                    if (s.Contains(".") && !ips.Contains(s)) ips.Add(s);
                }
            if (ips.Count > 0) a.Snapshot.Add("IP addresses", string.Join(", ", ips.ToArray()));

            var roleNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "AD-Domain-Services", "Active Directory" }, { "DNS", "DNS" }, { "DHCP", "DHCP" },
                { "FS-FileServer", "File server" }, { "Hyper-V", "Hyper-V" }, { "Web-Server", "IIS" },
                { "Print-Server", "Print server" }, { "RDS-RD-Server", "RD Session Host" }, { "RDS-Licensing", "RD Licensing" },
                { "RDS-Gateway", "RD Gateway" }, { "ADCS-Cert-Authority", "Certificate Authority" },
                { "Windows-Server-Backup", "Windows Server Backup" }, { "FS-DFS-Replication", "DFS Replication" },
                { "FS-DFS-Namespace", "DFS Namespaces" }, { "UpdateServices", "WSUS" }, { "NPAS", "NPS" }
            };
            var found = new List<string>();
            foreach (object row in C("ServerRoles").Data)
            {
                string name;
                if (roleNames.TryGetValue(J.Str(row, "Name"), out name) && !found.Contains(name)) found.Add(name);
            }
            if (found.Count > 0) a.Snapshot.Add("Server roles", string.Join(", ", found.ToArray()));
        }

        private void CollectionHealth()
        {
            if (!r.Elevated)
                Add("not-elevated", Severity.Critical, "Audit", "Audit was not run as administrator",
                    "Many checks could not read their data. Run the audit again from an elevated session.");
            if (r.Incomplete)
                Add("incomplete", Severity.Warning, "Audit", "Audit collection did not finish",
                    "This report was built from the last saved checkpoint. Run the audit again for complete results.");
        }

        // ---------------------------------------------------------------- lifecycle

        private void Lifecycle()
        {
            object sys = C("System").First;
            object osr = C("OSRelease").First;
            string caption = a.OsName;
            int build;
            int.TryParse(J.Str(sys, "Build").Length > 0 ? J.Str(sys, "Build") : J.Str(osr, "CurrentBuild"), out build);
            string edition = J.Str(osr, "EditionID");
            bool server = Match(caption, "Server") || Match(J.Str(osr, "InstallationType"), "Server");
            bool enterprise = Match(edition + " " + caption, "Enterprise|Education");

            string name = null; DateTime? end = null;
            if (server)
            {
                if (build >= 6000 && build <= 6003) { name = "Windows Server 2008"; end = new DateTime(2020, 1, 14); }
                else if (build == 7600 || build == 7601) { name = "Windows Server 2008 R2"; end = new DateTime(2020, 1, 14); }
                else if (build == 9200) { name = "Windows Server 2012"; end = new DateTime(2023, 10, 10); }
                else if (build == 9600) { name = "Windows Server 2012 R2"; end = new DateTime(2023, 10, 10); }
                else if (build == 14393) { name = "Windows Server 2016"; end = new DateTime(2027, 1, 12); }
                else if (build == 17763) { name = "Windows Server 2019"; end = new DateTime(2029, 1, 9); }
                else if (build == 20348) { name = "Windows Server 2022"; end = new DateTime(2031, 10, 14); }
                else if (build == 26100) { name = "Windows Server 2025"; end = new DateTime(2034, 11, 14); }
            }
            else
            {
                if (build >= 10240 && build <= 19045) { name = "Windows 10"; end = new DateTime(2025, 10, 14); }
                else if (build == 22000) { name = "Windows 11 21H2"; end = new DateTime(2024, 10, 8); }
                else if (build == 22621) { name = "Windows 11 22H2"; end = enterprise ? new DateTime(2025, 10, 14) : new DateTime(2024, 10, 8); }
                else if (build == 22631) { name = "Windows 11 23H2"; end = enterprise ? new DateTime(2026, 11, 10) : new DateTime(2025, 11, 11); }
                else if (build == 26100) { name = "Windows 11 24H2"; end = enterprise ? new DateTime(2027, 10, 12) : new DateTime(2026, 10, 13); }
                else if (build == 26200) { name = "Windows 11 25H2"; end = enterprise ? new DateTime(2028, 10, 10) : new DateTime(2027, 10, 12); }
            }

            if (name == null)
            {
                a.OsSupportSeverity = Severity.Unknown;
                a.OsSupportText = "Unknown";
                Add("os-lifecycle", Severity.Info, "Lifecycle", "Support lifecycle not recognised",
                    "Build " + build + " is not in the app's lifecycle table. Check the Microsoft lifecycle page.");
                return;
            }
            int daysLeft = (int)Math.Floor((end.Value - now.Date).TotalDays);
            if (daysLeft < 0)
            {
                a.OsSupportSeverity = Severity.Critical;
                a.OsSupportText = "Out of support since " + J.FormatDate(end);
                a.OsNeedsEntitlementCheck = true;
                Add("os-lifecycle", Severity.Critical, "Lifecycle", name + " is out of support",
                    "Microsoft support ended " + J.FormatDate(end) + ". The server no longer receives security updates unless it is covered by Extended Security Updates. Plan an upgrade or replacement.");
            }
            else if (daysLeft <= 365)
            {
                a.OsSupportSeverity = Severity.Warning;
                a.OsSupportText = "Support ends " + J.FormatDate(end);
                a.OsNeedsEntitlementCheck = true;
                Add("os-lifecycle", Severity.Warning, "Lifecycle", name + " support ends in " + J.Plural(daysLeft, "day", "days"),
                    "Extended support ends " + J.FormatDate(end) + ". Start planning the upgrade or replacement.");
            }
            else
            {
                a.OsSupportSeverity = Severity.Pass;
                a.OsSupportText = "Supported until " + J.FormatDate(end);
                Add("os-lifecycle", Severity.Pass, "Lifecycle", name + " is supported", "Support continues until " + J.FormatDate(end) + ".");
            }
            int buildIndex = a.Snapshot.Items.FindIndex(i => i.Key == "Build");
            a.Snapshot.Items.Insert(buildIndex >= 0 ? buildIndex + 1 : a.Snapshot.Items.Count, new KeyValuePair<string, string>("Support status", a.OsSupportText));
        }

        // ---------------------------------------------------------------- patching

        private void Patching()
        {
            var sec = new Section("Windows Update");
            var kv = new KeyValueBlock();
            sec.Blocks.Add(kv);

            object sys = C("System").First;
            double? uptime = J.Num(sys, "UptimeDays");
            if (uptime.HasValue)
            {
                if (uptime.Value > 35)
                    Add("uptime", Severity.Warning, "Patching", "Not restarted in " + Math.Floor(uptime.Value) + " days",
                        "Monthly updates normally need a restart to finish installing. Schedule a maintenance restart.");
                else
                    Add("uptime", Severity.Pass, "Patching", "Restarted within the last 35 days", "Last restart " + J.FormatDateTime(J.Date(sys, "LastBoot")) + ".");
            }

            CheckResult pr = C("PendingReboot");
            if (pr.Ok)
            {
                var reasons = new List<string>();
                if (J.Bool(pr.First, "ComponentServicing") == true) reasons.Add("component servicing");
                if (J.Bool(pr.First, "WindowsUpdate") == true) reasons.Add("Windows Update");
                if (J.Bool(pr.First, "PendingFileRename") == true) reasons.Add("pending file renames");
                if (reasons.Count > 0)
                    Add("pending-reboot", Severity.Warning, "Patching", "Restart pending",
                        "Waiting on: " + string.Join(", ", reasons.ToArray()) + ". Updates are not fully applied until the server restarts.");
                else
                    Add("pending-reboot", Severity.Pass, "Patching", "No restart pending", "");
                kv.Add("Restart pending", reasons.Count > 0 ? "Yes — " + string.Join(", ", reasons.ToArray()) : "No");
            }

            // Missing updates: prefer the live scan, fall back to the local cache.
            CheckResult live = C("LiveMissingUpdates"), cached = C("CachedMissingUpdates");
            CheckResult src = null; string srcText = "";
            if (live.Ok && IsWuSuccess(live.First)) { src = live; srcText = "live scan"; }
            else if (cached.Ok && IsWuSuccess(cached.First)) { src = cached; srcText = "local update cache (may be out of date)"; }
            var missingTable = new TableBlock("Missing updates", new[] { "Update", "Severity", "KB" }, new[] { 6.0, 1.3, 1.3 });
            missingTable.EmptyText = "No missing updates found.";
            if (src != null)
            {
                var updates = J.List(J.Get(src.First, "Updates"));
                bool anyCritical = false;
                foreach (object u in updates)
                {
                    string severity = J.Str(u, "MsrcSeverity");
                    if (severity == "Critical") anyCritical = true;
                    Severity chip = severity == "Critical" ? Severity.Critical : severity == "Important" ? Severity.Warning : Severity.Info;
                    string kb = J.Str(u, "KBArticleIDs");
                    missingTable.Add(J.Str(u, "Title"), new Cell(severity.Length > 0 ? severity : "Unrated", chip), kb.Length > 0 ? "KB" + kb.Replace(", ", ", KB") : "");
                }
                if (updates.Count > 0)
                {
                    var titles = updates.Take(4).Select(u => J.Shorten(J.Str(u, "Title"), 90)).ToArray();
                    Add("missing-updates", anyCritical ? Severity.Critical : Severity.Warning, "Patching",
                        J.Plural(updates.Count, "update is", "updates are") + " not installed",
                        "From the " + srcText + ": " + string.Join("; ", titles) + (updates.Count > 4 ? "; …" : "") + ".");
                }
                else Add("missing-updates", Severity.Pass, "Patching", "No missing updates", "Checked using the " + srcText + ".");
                kv.Add("Missing updates", updates.Count + " (" + srcText + ")");
            }

            // Update history: last success and recent failures.
            CheckResult hist = C("UpdateHistory");
            var recent = new TableBlock("Recently installed updates", new[] { "Installed", "Update" }, new[] { 1.3, 6.0 });
            if (hist.Ok)
            {
                var installs = hist.Data.Where(h => (J.Num(h, "Operation") ?? 0) == 1 || J.Str(h, "Operation") == "Installation").ToList();
                var ok = installs.Where(h => { double rc = J.Num(h, "ResultCode") ?? -1; return rc == 2 || rc == 3; })
                    .OrderByDescending(h => J.Date(h, "Date") ?? DateTime.MinValue).ToList();
                DateTime? last = ok.Count > 0 ? J.Date(ok[0], "Date") : null;
                if (last.HasValue)
                {
                    int age = DaysSince(last);
                    kv.Add("Last update installed", J.FormatDate(last) + " (" + age + " days ago)");
                    if (age > 60) Add("update-age", Severity.Critical, "Patching", "No updates installed in " + age + " days", "Last successful install " + J.FormatDate(last) + ". Check Windows Update / RMM patch policy for this server.");
                    else if (age > 35) Add("update-age", Severity.Warning, "Patching", "No updates installed in " + age + " days", "Last successful install " + J.FormatDate(last) + ".");
                    else Add("update-age", Severity.Pass, "Patching", "Updates installed in the last 35 days", "Last successful install " + J.FormatDate(last) + ".");
                }
                foreach (object h in ok.Take(8)) recent.Add(J.FormatDate(J.Date(h, "Date")), J.Str(h, "Title"));

                var since = now.AddDays(-30);
                var failed = installs.Where(h => { double rc = J.Num(h, "ResultCode") ?? -1; DateTime? d = J.Date(h, "Date"); return (rc == 4 || rc == 5) && d.HasValue && d.Value >= since; })
                    .Select(h => J.Str(h, "Title")).Distinct()
                    .Where(t => !ok.Any(s => J.Str(s, "Title") == t)) // later succeeded
                    .ToList();
                if (failed.Count > 0)
                    Add("update-failures", Severity.Warning, "Patching", J.Plural(failed.Count, "update failed", "updates failed") + " to install in the last 30 days",
                        string.Join("; ", failed.Take(4).Select(t => J.Shorten(t, 90)).ToArray()) + (failed.Count > 4 ? "; …" : "") + ".");
            }
            else
            {
                var hotfixes = C("Hotfixes").Data.Select(h => J.Date(h, "InstalledOn")).Where(d => d.HasValue).OrderByDescending(d => d).ToList();
                if (hotfixes.Count > 0) kv.Add("Last hotfix installed", J.FormatDate(hotfixes[0]));
            }

            object time = C("TimeService").First;
            string timeText = J.Str(time);
            if (timeText.Length > 0)
            {
                Match src2 = Regex.Match(timeText, @"Source:\s*(.+)");
                string source = src2.Success ? src2.Groups[1].Value.Trim() : "";
                if (Match(source, "Local CMOS Clock|Free-running System Clock"))
                    Add("time-sync", a.IsDomainController ? Severity.Warning : Severity.Warning, "System", "Clock is not syncing with a time source",
                        "Time source is \"" + source + "\". Kerberos and logs depend on accurate time.");
                else if (source.Length > 0)
                    Add("time-sync", Severity.Pass, "System", "Clock syncing with " + J.Shorten(source, 60), "");
                if (source.Length > 0) kv.Add("Time source", source);
            }

            sec.Blocks.Add(missingTable);
            if (recent.Rows.Count > 0) sec.Blocks.Add(recent);
            a.Sections.Add(sec);
        }

        private static bool IsWuSuccess(object first)
        {
            double rc = J.Num(first, "ResultCode") ?? -1;
            return rc == 2 || rc == 3;
        }

        // ---------------------------------------------------------------- security

        private void Security()
        {
            var sec = new Section("Security");
            var controls = new TableBlock("Security controls", new[] { "Control", "Status", "Detail" }, new[] { 2.4, 1.3, 4.3 });
            var agentsTable = new TableBlock("Agents and remote access services", new[] { "Service", "Name", "State", "Startup" }, new[] { 2.6, 2.6, 1.1, 1.0 });
            agentsTable.EmptyText = "No management, security or remote access services detected.";

            // Agents: RMM, EDR and anything else from the expected list.
            CheckResult agents = C("AgentServices");
            if (agents.Ok)
            {
                foreach (object s in agents.Data)
                {
                    string state = J.Str(s, "State"), start = J.Str(s, "StartMode");
                    Severity chip = state == "Running" ? Severity.Pass : (start == "Auto" ? Severity.Critical : Severity.Info);
                    agentsTable.Add(J.Str(s, "DisplayName"), J.Str(s, "Name"), new Cell(state, chip), start);
                }
                foreach (string expected in expectedAgents)
                {
                    string pattern = expected.Trim();
                    if (pattern.Length == 0) continue;
                    var matches = agents.Data.Where(s => J.Str(s, "Name").IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0
                        || J.Str(s, "DisplayName").IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0).ToList();
                    string key = "agent-" + pattern.ToLowerInvariant();
                    if (matches.Count == 0)
                        Add(key, Severity.Critical, "Security", pattern + " agent is not installed",
                            "No service matching \"" + pattern + "\" was found. Install the agent or confirm this server is intentionally excluded.");
                    else
                    {
                        var stopped = matches.Where(s => J.Str(s, "StartMode") == "Auto" && J.Str(s, "State") != "Running").ToList();
                        if (stopped.Count > 0)
                            Add(key, Severity.Critical, "Security", pattern + " agent service is stopped",
                                string.Join(", ", stopped.Select(s => J.Str(s, "DisplayName") + " (" + J.Str(s, "State") + ")").ToArray()) + ". Start the service and check the console.");
                        else
                            Add(key, Severity.Pass, "Security", pattern + " agent running", string.Join(", ", matches.Select(s => J.Str(s, "DisplayName")).Distinct().ToArray()));
                    }
                }
                var remote = agents.Data.Where(s => Match(J.Str(s, "Name") + " " + J.Str(s, "DisplayName"), @"TeamViewer|AnyDesk|Splashtop|RustDesk|VNC|LogMeIn|GoTo|ScreenConnect|ConnectWise Control|BeyondTrust|Bomgar"))
                    .Select(s => J.Str(s, "DisplayName")).Distinct().ToList();
                if (remote.Count > 0)
                    Add("remote-tools", Severity.Info, "Security", "Remote access software installed",
                        string.Join(", ", remote.ToArray()) + ". Confirm each tool is approved and still needed.");
            }

            // Defender / antivirus.
            var thirdPartyAv = new List<string>();
            foreach (object p in C("Antivirus").Data)
            {
                string n = J.Str(p, "displayName");
                if (n.Length > 0 && !Match(n, "Windows Defender|Microsoft Defender")) thirdPartyAv.Add(n);
            }
            foreach (object s in agents.Data)
                if (Match(J.Str(s, "Name") + " " + J.Str(s, "DisplayName"), "Sentinel|Sophos|CrowdStrike|Webroot|ESET|Bitdefender") && J.Str(s, "State") == "Running")
                    thirdPartyAv.Add(J.Str(s, "DisplayName"));
            CheckResult def = C("Defender");
            if (def.Ok)
            {
                object d = def.First;
                bool? rtp = J.Bool(d, "RealTimeProtectionEnabled");
                bool? av = J.Bool(d, "AntivirusEnabled");
                if (rtp == false || av == false)
                {
                    if (thirdPartyAv.Count > 0)
                        Add("defender-rtp", Severity.Info, "Security", "Defender real-time protection is off",
                            "Another antivirus appears to be active: " + string.Join(", ", thirdPartyAv.Distinct().ToArray()) + ".");
                    else
                        Add("defender-rtp", Severity.Critical, "Security", "Antivirus real-time protection is off",
                            "Microsoft Defender real-time protection is disabled and no other antivirus was detected.");
                }
                else if (rtp == true) Add("defender-rtp", Severity.Pass, "Security", "Defender real-time protection on", "");
                controls.Add("Defender real-time protection", Chip(rtp, "On", "Off"), "");

                DateTime? sig = J.Date(d, "AntivirusSignatureLastUpdated");
                if (sig.HasValue && rtp != false)
                {
                    int age = DaysSince(sig);
                    Severity s = age > 7 ? Severity.Critical : age > 3 ? Severity.Warning : Severity.Pass;
                    if (s == Severity.Pass) Add("defender-signatures", s, "Security", "Antivirus signatures current", "Updated " + J.FormatDateTime(sig) + ".");
                    else Add("defender-signatures", s, "Security", "Antivirus signatures are " + age + " days old", "Last updated " + J.FormatDateTime(sig) + ". Check Defender update source/connectivity.");
                    controls.Add("Defender signatures", new Cell(age + " days old", s), J.Str(d, "AntivirusSignatureVersion"));
                }
                bool? tamper = J.Bool(d, "IsTamperProtected");
                if (tamper.HasValue) controls.Add("Defender tamper protection", Chip(tamper, "On", "Off", Severity.Info), "");
                DateTime? quick = J.Date(d, "QuickScanEndTime");
                if (quick.HasValue) controls.Add("Last quick scan", new Cell(J.FormatDate(quick)), "");
            }
            else if (thirdPartyAv.Count > 0) controls.Add("Antivirus", new Cell("Detected", Severity.Pass), string.Join(", ", thirdPartyAv.Distinct().ToArray()));

            // Firewall.
            CheckResult fw = C("Firewall");
            if (fw.Ok)
            {
                var off = new List<string>();
                foreach (object p in fw.Data)
                {
                    bool? en = J.Bool(p, "Enabled");
                    double? n = J.Num(J.Get(p, "Enabled"));
                    if (n.HasValue && n.Value == 2) en = null; // GpoBoolean NotConfigured
                    string profile = J.Str(p, "Name");
                    if (en == false) off.Add(profile);
                    controls.Add("Firewall — " + profile + " profile", Chip(en, "On", "Off", Severity.Warning), "");
                }
                if (off.Count > 0) Add("firewall", Severity.Warning, "Security", "Windows Firewall is off (" + string.Join(", ", off.ToArray()) + ")", "Turn the firewall back on or document the compensating control.");
                else Add("firewall", Severity.Pass, "Security", "Windows Firewall on for all profiles", "");
            }

            // RDP.
            CheckResult rdp = C("RDP");
            if (rdp.Ok)
            {
                object d = rdp.First;
                bool enabled = (J.Num(d, "DenyConnections") ?? 1) == 0;
                bool nla = (J.Num(d, "RequireNLA") ?? 0) == 1;
                string port = J.Str(d, "Port");
                if (!enabled) { controls.Add("Remote Desktop", new Cell("Disabled", Severity.Pass), ""); }
                else
                {
                    controls.Add("Remote Desktop", new Cell("Enabled", Severity.Info), "Port " + port);
                    controls.Add("RDP Network Level Authentication", new Cell(nla ? "Required" : "Not required", nla ? Severity.Pass : Severity.Critical), "");
                    if (!nla) Add("rdp-nla", Severity.Critical, "Security", "Remote Desktop does not require NLA", "Users can reach the logon screen before authenticating. Require Network Level Authentication.");
                    else Add("rdp-nla", Severity.Pass, "Security", "Remote Desktop requires NLA", "");
                }
            }

            // SMB.
            CheckResult smb = C("SMB");
            if (smb.Ok)
            {
                bool? smb1 = J.Bool(smb.First, "EnableSMB1Protocol");
                bool? signing = J.Bool(smb.First, "RequireSecuritySignature");
                controls.Add("SMBv1", new Cell(smb1 == true ? "Enabled" : smb1 == false ? "Disabled" : "Unknown", smb1 == true ? Severity.Critical : smb1 == false ? Severity.Pass : Severity.Unknown), "");
                controls.Add("SMB signing required", Chip(signing, "Yes", "No", Severity.Info), "");
                if (smb1 == true) Add("smb1", Severity.Critical, "Security", "SMBv1 is enabled", "SMBv1 is obsolete and exploitable (WannaCry). Disable it unless a documented legacy device needs it.");
                else if (smb1 == false) Add("smb1", Severity.Pass, "Security", "SMBv1 disabled", "");
                if (signing == false && a.IsDomainController) Add("smb-signing", Severity.Warning, "Security", "SMB signing not required on a domain controller", "");
            }

            // BitLocker / Secure Boot / TPM.
            CheckResult bl = C("BitLocker");
            if (bl.Ok)
            {
                object osVol = bl.Data.FirstOrDefault(v => J.Str(v, "VolumeType") == "OperatingSystem" || (J.Num(J.Get(v, "VolumeType")) == 0 && !(J.Get(v, "VolumeType") is string)))
                    ?? bl.Data.FirstOrDefault(v => J.Str(v, "MountPoint").StartsWith("C:", StringComparison.OrdinalIgnoreCase));
                if (osVol != null)
                {
                    object ps = J.Get(osVol, "ProtectionStatus");
                    bool on = J.Str(ps) == "On" || (!(ps is string) && J.Num(ps) == 1);
                    controls.Add("BitLocker (system drive)", new Cell(on ? "On" : "Off", on ? Severity.Pass : (a.IsVirtual ? Severity.Info : Severity.Warning)), J.Str(osVol, "EncryptionMethod"));
                    if (!on && !a.IsVirtual) Add("bitlocker", Severity.Warning, "Security", "System drive is not BitLocker-encrypted", "Physical server disks hold unencrypted data if a drive is removed or the server is stolen.");
                }
            }
            CheckResult sb = C("SecureBoot");
            if (sb.Ok) controls.Add("Secure Boot", Chip(J.Bool(sb.First, "Enabled"), "On", "Off", Severity.Info), "");
            CheckResult tpm = C("TPM");
            if (tpm.Ok) controls.Add("TPM", Chip(J.Bool(tpm.First, "TpmPresent"), "Present", "Not present", Severity.Info), J.Str(tpm.First, "ManufacturerIdTxt"));

            // Shares open to Everyone.
            var special = new HashSet<string>(C("Shares").Data.Where(s => J.Bool(s, "Special") == true).Select(s => J.Str(s, "Name")), StringComparer.OrdinalIgnoreCase);
            var shareTable = new TableBlock("File shares", new[] { "Share", "Path", "Access" }, new[] { 1.6, 2.6, 3.8 });
            shareTable.EmptyText = "No non-administrative shares.";
            var shareAccess = C("SharePermissions").Data;
            foreach (object s in C("Shares").Data.Where(x => J.Bool(x, "Special") != true))
            {
                string name = J.Str(s, "Name");
                var acl = shareAccess.Where(p => string.Equals(J.Str(p, "Name"), name, StringComparison.OrdinalIgnoreCase))
                    .Select(p => J.Str(p, "AccountName") + ": " + AccessRight(J.Get(p, "AccessRight")) + (IsDeny(J.Get(p, "AccessControlType")) ? " (deny)" : ""))
                    .ToArray();
                shareTable.Add(name, J.Str(s, "Path"), string.Join("; ", acl));
            }
            var open = shareAccess.Where(p => !special.Contains(J.Str(p, "Name")) && Match(J.Str(p, "AccountName"), @"^(Everyone|.*\\Everyone)$")
                && !IsDeny(J.Get(p, "AccessControlType")) && (AccessRight(J.Get(p, "AccessRight")) == "Full" || AccessRight(J.Get(p, "AccessRight")) == "Change"))
                .Select(p => J.Str(p, "Name") + " (" + AccessRight(J.Get(p, "AccessRight")) + ")").Distinct().ToList();
            if (open.Count > 0)
                Add("share-everyone", Severity.Warning, "Security", "Shares give Everyone write access",
                    string.Join(", ", open.ToArray()) + ". Share permissions should name groups; rely on NTFS permissions to narrow access.");

            // Password / lockout policy.
            var policy = new Dictionary<string, double?>(StringComparer.OrdinalIgnoreCase);
            foreach (object p in C("SecurityPolicy").Data) policy[J.Str(p, "Name")] = J.Num(p, "Value");
            double? minLen, lockout, complexity;
            policy.TryGetValue("MinimumPasswordLength", out minLen);
            policy.TryGetValue("LockoutBadCount", out lockout);
            policy.TryGetValue("PasswordComplexity", out complexity);
            string scope = a.IsDomainController ? "Domain" : "Local";
            if (minLen.HasValue)
            {
                controls.Add(scope + " minimum password length", new Cell(minLen.Value.ToString(CultureInfo.InvariantCulture), minLen.Value < 8 ? Severity.Warning : minLen.Value < 12 ? Severity.Info : Severity.Pass), "");
                if (minLen.Value < 8) Add("password-length", Severity.Warning, "Accounts", scope + " minimum password length is " + minLen.Value, "Set at least 12 characters (14 recommended).");
            }
            if (complexity.HasValue)
            {
                controls.Add(scope + " password complexity", new Cell(complexity.Value == 1 ? "On" : "Off", complexity.Value == 1 ? Severity.Pass : Severity.Warning), "");
                if (complexity.Value == 0) Add("password-complexity", Severity.Warning, "Accounts", scope + " password complexity is off", "");
            }
            if (lockout.HasValue)
            {
                controls.Add(scope + " account lockout", new Cell(lockout.Value == 0 ? "Off" : "After " + lockout.Value + " attempts", lockout.Value == 0 ? Severity.Warning : Severity.Pass), "");
                if (lockout.Value == 0) Add("lockout", Severity.Warning, "Accounts", scope + " account lockout is not configured", "Unlimited password guesses are allowed. Set a lockout threshold (for example 10 attempts).");
            }

            // Failed logons.
            CheckResult fl = C("FailedLogons");
            if (fl.Ok && fl.First != null)
            {
                object e = fl.First;
                var events = J.List(J.Get(e, "Events"));
                int count = (int)(J.Num(e, "MatchedInSample") ?? events.Count);
                bool more = J.Bool(e, "QueryLimitReached") == true;
                var users = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                var ipsSeen = new Dictionary<string, int>();
                foreach (object ev in events)
                {
                    foreach (object f in J.List(J.Get(ev, "EventData")))
                    {
                        string n = J.Str(f, "Name"), v = J.Str(f, "Value");
                        if (v.Length == 0 || v == "-") continue;
                        if (n == "TargetUserName") users[v] = (users.ContainsKey(v) ? users[v] : 0) + 1;
                        if (n == "IpAddress") ipsSeen[v] = (ipsSeen.ContainsKey(v) ? ipsSeen[v] : 0) + 1;
                    }
                }
                string top = "";
                if (users.Count > 0) top += " Top accounts: " + string.Join(", ", users.OrderByDescending(x => x.Value).Take(4).Select(x => x.Key + " (" + x.Value + ")").ToArray()) + ".";
                if (ipsSeen.Count > 0) top += " Top sources: " + string.Join(", ", ipsSeen.OrderByDescending(x => x.Value).Take(4).Select(x => x.Key + " (" + x.Value + ")").ToArray()) + ".";
                string countText = more ? count + "+" : count.ToString(CultureInfo.InvariantCulture);
                if (more || count >= 50) Add("failed-logons", Severity.Warning, "Security", countText + " failed logons in the last 30 days", "Review for password spraying or a misconfigured service." + top);
                else if (count > 0) Add("failed-logons", Severity.Info, "Security", countText + " failed logons in the last 30 days", top.Trim());
                else Add("failed-logons", Severity.Pass, "Security", "No failed logons in the last 30 days", "");
                controls.Add("Failed logons (30 days)", new Cell(countText, more || count >= 50 ? Severity.Warning : count > 0 ? Severity.Info : Severity.Pass), "");
            }

            sec.Blocks.Add(controls);
            sec.Blocks.Add(agentsTable);
            sec.Blocks.Add(shareTable);
            a.Sections.Add(sec);
        }

        private static Cell Chip(bool? value, string yes, string no) { return Chip(value, yes, no, Severity.Critical); }

        private static Cell Chip(bool? value, string yes, string no, Severity whenNo)
        {
            if (!value.HasValue) return new Cell("Unknown", Severity.Unknown);
            return value.Value ? new Cell(yes, Severity.Pass) : new Cell(no, whenNo);
        }

        private static string AccessRight(object v)
        {
            string s = J.Str(v);
            if (v is string) return s;
            switch ((int)(J.Num(v) ?? -1)) { case 0: return "Full"; case 1: return "Change"; case 2: return "Read"; case 3: return "Custom"; default: return s; }
        }

        private static bool IsDeny(object v)
        {
            return J.Str(v) == "Deny" || (!(v is string) && J.Num(v) == 1);
        }

        // ---------------------------------------------------------------- storage

        private void Storage()
        {
            var sec = new Section("Storage");
            var bars = new BarBlock();
            sec.Blocks.Add(bars);
            CheckResult disks = C("Disks");
            if (disks.Ok)
            {
                bool allGood = true;
                foreach (object d in disks.Data.OrderBy(x => J.Str(x, "DeviceID")))
                {
                    string id = J.Str(d, "DeviceID"), label = J.Str(d, "VolumeName");
                    double? size = J.Num(d, "SizeGB"), free = J.Num(d, "FreeGB"), pct = J.Num(d, "FreePercent");
                    if (!size.HasValue || size.Value <= 0) continue;
                    if (!pct.HasValue && free.HasValue) pct = 100 * free.Value / size.Value;
                    Severity s = pct < 10 ? Severity.Critical : pct < 20 ? Severity.Warning : Severity.Pass;
                    if (s != Severity.Pass)
                    {
                        allGood = false;
                        Add("disk-" + id, s, "Storage", "Drive " + id + " is low on space",
                            Gb(free) + " free of " + Gb(size) + " (" + Math.Round(pct ?? 0, 1) + "%). Clean up or extend the volume before it fills.");
                    }
                    bars.Items.Add(new BarItem
                    {
                        Label = id + (label.Length > 0 ? "  " + label : ""),
                        Right = Gb(free) + " free of " + Gb(size),
                        UsedFraction = Math.Max(0, Math.Min(1, 1 - (pct ?? 0) / 100)),
                        Severity = s
                    });
                }
                if (allGood && bars.Items.Count > 0) Add("disk-space", Severity.Pass, "Storage", "All drives have at least 20% free space", "");
            }

            var health = new TableBlock("Disk health", new[] { "Disk", "Type", "Size", "Health" }, new[] { 3.5, 1.2, 1.2, 1.3 });
            foreach (object d in C("PhysicalDisks").Data)
            {
                Severity s = HealthSeverity(J.Get(d, "HealthStatus"));
                string name = J.Str(d, "FriendlyName");
                health.Add(name, MediaType(J.Get(d, "MediaType")), Gb((J.Num(d, "Size") ?? 0) / 1073741824.0), new Cell(HealthText(J.Get(d, "HealthStatus")), s));
                if (s == Severity.Critical || s == Severity.Warning)
                    Add("pdisk-" + name, Severity.Critical, "Storage", "Disk \"" + name + "\" reports " + HealthText(J.Get(d, "HealthStatus")), "Check the RAID controller / storage console and replace the disk if needed.");
            }
            foreach (object v in C("Volumes").Data)
            {
                Severity s = HealthSeverity(J.Get(v, "HealthStatus"));
                if (s == Severity.Critical || s == Severity.Warning)
                {
                    string letter = J.Str(v, "DriveLetter");
                    Add("volume-" + letter, Severity.Warning, "Storage", "Volume " + (letter.Length > 0 ? letter + ":" : J.Str(v, "FileSystemLabel")) + " reports " + HealthText(J.Get(v, "HealthStatus")), "Run a file system check during the next maintenance window.");
                }
            }
            foreach (object rel in C("StorageReliability").Data)
            {
                foreach (object c in J.List(J.Get(rel, "Counters")))
                {
                    double? uncorrected = (J.Num(c, "ReadErrorsUncorrected") ?? 0) + (J.Num(c, "WriteErrorsUncorrected") ?? 0);
                    double? temp = J.Num(c, "Temperature");
                    string disk = J.Str(rel, "Disk");
                    if (uncorrected > 0) Add("disk-errors-" + disk, Severity.Warning, "Storage", "Disk \"" + disk + "\" has uncorrected read/write errors", uncorrected + " uncorrected errors reported by the drive.");
                    if (temp.HasValue && temp.Value >= 60) Add("disk-temp-" + disk, Severity.Warning, "Storage", "Disk \"" + disk + "\" is running hot (" + temp + " °C)", "Check cooling and airflow.");
                }
            }
            if (health.Rows.Count > 0) sec.Blocks.Add(health);

            EventFinding("StorageErrorDetails", "storage-events", "Storage", "disk/storage error", "disk/storage errors", "in the System log in the last 30 days. Check cabling, controller and drive health.", Severity.Warning, true);
            CheckResult sd = C("UnexpectedShutdowns");
            if (sd.Ok && sd.First != null)
            {
                var evs = J.List(J.Get(sd.First, "Events")).Where(e => { double id = J.Num(e, "Id") ?? 0; return id == 41 || id == 6008; }).ToList();
                if (evs.Count > 0)
                    Add("unexpected-shutdowns", Severity.Warning, "System", J.Plural(evs.Count, "unexpected shutdown", "unexpected shutdowns") + " in the last 30 days",
                        "Most recent " + J.FormatDateTime(evs.Select(e => J.Date(e, "TimeCreated")).Max()) + ". Check power, UPS, hardware logs and crash dumps.");
            }
            a.Sections.Add(sec);
        }

        private static string MediaType(object v)
        {
            if (v is string) return (string)v;
            switch ((int)(J.Num(v) ?? 0)) { case 3: return "HDD"; case 4: return "SSD"; case 5: return "SCM"; default: return "Unspecified"; }
        }

        /// <summary>Adds a finding summarising error events in an event-sample check.</summary>
        private int EventFinding(string check, string key, string area, string one, string many, string suffix, Severity sev, bool passIfNone)
        {
            CheckResult c = C(check);
            if (!c.Ok || c.First == null) return -1;
            var events = J.List(J.Get(c.First, "Events")).Where(e => { double lvl = J.Num(e, "Level") ?? 4; return lvl == 1 || lvl == 2; }).ToList();
            if (events.Count == 0)
            {
                if (passIfNone) Add(key, Severity.Pass, area, "No " + many + " logged", "");
                return 0;
            }
            var byProvider = events.GroupBy(e => J.Str(e, "ProviderName") + " " + J.Str(e, "Id")).OrderByDescending(g => g.Count()).Take(3)
                .Select(g => g.Key + " ×" + g.Count()).ToArray();
            string sample = "";
            object withMessage = events.FirstOrDefault(e => J.Str(e, "Message").Length > 0);
            if (withMessage != null) sample = " Latest: \"" + J.Shorten(J.Str(withMessage, "Message"), 160) + "\"";
            bool truncated = J.Bool(c.First, "OutputTruncated") == true;
            Add(key, sev, area, (truncated ? events.Count + "+ " : events.Count + " ") + (events.Count == 1 ? one : many),
                "Logged " + suffix + " Sources: " + string.Join(", ", byProvider) + "." + sample);
            return events.Count;
        }

        // ---------------------------------------------------------------- backups

        private void Backups()
        {
            var sec = new Section("Backups");
            var kv = new KeyValueBlock();
            sec.Blocks.Add(kv);

            var products = C("BackupSoftware").Data.Select(p => (J.Str(p, "DisplayName") + " " + J.Str(p, "DisplayVersion")).Trim())
                .Where(p => p.Length > 0 && !Match(p, "OneDrive")).Distinct().ToList();
            var services = C("BackupServices").Data.Where(s => !Match(J.Str(s, "Name"), "^(VSS|swprv|SDRSVC|wbengine)$") && !Match(J.Str(s, "DisplayName"), "OneDrive")).ToList();
            kv.Add("Backup software", products.Count > 0 ? string.Join(", ", products.ToArray()) : "None detected");

            var svcTable = new TableBlock("Backup services", new[] { "Service", "State", "Startup" }, new[] { 4.5, 1.2, 1.2 });
            foreach (object s in services)
            {
                string state = J.Str(s, "State"), start = J.Str(s, "StartMode");
                bool bad = start == "Auto" && state != "Running";
                svcTable.Add(J.Str(s, "DisplayName"), new Cell(state, bad ? Severity.Critical : state == "Running" ? Severity.Pass : Severity.Info), start);
                if (bad) Add("backup-svc-" + J.Str(s, "Name"), Severity.Critical, "Backups", "Backup service stopped: " + J.Str(s, "DisplayName"), "The service is set to start automatically but is " + state + ".");
            }

            // Windows Server Backup.
            bool wsbConfigured = false;
            CheckResult wsbPolicy = C("WindowsBackupPolicy");
            if (wsbPolicy.Ok) wsbConfigured = J.Bool(wsbPolicy.First, "PolicyConfigured") == true;
            CheckResult wsb = C("WindowsBackupSummary");
            if (wsb.Ok && wsb.First != null)
            {
                DateTime? lastOk = J.Date(wsb.First, "LastSuccessfulBackupTime");
                DateTime? last = J.Date(wsb.First, "LastBackupTime");
                double hr = J.Num(wsb.First, "LastBackupResultHR") ?? 0;
                if (lastOk.HasValue || wsbConfigured)
                {
                    kv.Add("Windows Server Backup", (wsbConfigured ? "Scheduled" : "Not scheduled") + " — last success " + J.FormatDateTime(lastOk) + ", next " + J.FormatDateTime(J.Date(wsb.First, "NextBackupTime")));
                    int age = DaysSince(lastOk);
                    if (!lastOk.HasValue) Add("wsb-age", Severity.Critical, "Backups", "Windows Server Backup has never succeeded", "A backup policy exists but no successful backup is recorded.");
                    else if (age > 2 && wsbConfigured) Add("wsb-age", Severity.Critical, "Backups", "Windows Server Backup last succeeded " + age + " days ago", "Last success " + J.FormatDateTime(lastOk) + ". Check the backup target and the Microsoft-Windows-Backup log.");
                    else Add("wsb-age", Severity.Pass, "Backups", "Windows Server Backup succeeded " + J.FormatDateTime(lastOk), "");
                    if (hr != 0 && last.HasValue)
                        Add("wsb-result", Severity.Warning, "Backups", "Last Windows Server Backup run failed", "Run at " + J.FormatDateTime(last) + " returned 0x" + unchecked((uint)(long)hr).ToString("X8") + ".");
                }
            }
            if (wsbConfigured)
            {
                var targets = J.List(J.Get(wsbPolicy.First, "Targets")).Select(t => J.Str(t, "Label") + " " + J.Str(t, "NetworkPath")).Select(t => t.Trim()).Where(t => t.Length > 0).ToArray();
                if (targets.Length > 0) kv.Add("WSB target", string.Join(", ", targets));
            }

            // Backup-related scheduled tasks.
            var taskTable = new TableBlock("Backup scheduled tasks", new[] { "Task", "Last run", "Result", "Next run" }, new[] { 3.6, 1.6, 1.3, 1.6 });
            int relevantTasks = 0;
            foreach (object t in C("BackupTasks").Data.Where(x => J.Str(x, "RecordType") == "Task"))
            {
                string path = J.Str(t, "TaskPath"), name = J.Str(t, "TaskName");
                var reasons = J.List(J.Get(t, "CandidateReasons")).Select(x => J.Str(x)).ToList();
                string exes = string.Join(" ", J.List(J.Get(t, "Actions")).Select(x => J.Str(x, "Execute")).ToArray());
                bool strong = Match(path + name + " " + exes, @"backup|veeam|acronis|macrium|datto|wbadmin|robocopy|rclone|restic|duplicati|\bcove\b|axcient|idrive|backblaze|synology active|sqlcmd|mysqldump|pg_dump")
                    || reasons.Contains("ReferencedScriptIndicator");
                if (!strong) continue;
                if (path.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase) && !Match(path + name, "WindowsBackup|Backup")) continue;
                if (Match(name, @"OneDrive|Update Task|Reporting|Telemetry")) continue;
                relevantTasks++;
                bool enabled = J.Bool(t, "Enabled") ?? (J.Str(t, "State") != "Disabled");
                double? res = J.Num(t, "LastTaskResult");
                DateTime? lastRun = J.Date(t, "LastRunTime");
                string resText; Severity resSev;
                if (!lastRun.HasValue) { resText = "Never run"; resSev = enabled ? Severity.Warning : Severity.Info; }
                else if (!res.HasValue) { resText = "Unknown"; resSev = Severity.Unknown; }
                else if (res.Value == 0) { resText = "Success"; resSev = Severity.Pass; }
                else if (res.Value == 267009) { resText = "Running"; resSev = Severity.Info; }
                else if (res.Value == 267008 || res.Value == 267011) { resText = "Not run"; resSev = Severity.Info; }
                else { resText = "0x" + unchecked((uint)(long)res.Value).ToString("X"); resSev = Severity.Warning; }
                if (!enabled) { resText += " (disabled)"; resSev = Severity.Info; }
                taskTable.Add((path.TrimEnd('\\') + "\\" + name).TrimStart('\\'), J.FormatDateTime(lastRun), new Cell(resText, resSev), J.FormatDateTime(J.Date(t, "NextRunTime")));
                if (enabled && resSev == Severity.Warning && lastRun.HasValue)
                    Add("task-" + name, Severity.Warning, "Backups", "Backup task \"" + name + "\" last run failed", "Last run " + J.FormatDateTime(lastRun) + " returned " + resText + ".");
                else if (enabled && lastRun.HasValue && DaysSince(lastRun) > 8 && J.List(J.Get(t, "Triggers")).Count > 0)
                    Add("task-stale-" + name, Severity.Warning, "Backups", "Backup task \"" + name + "\" has not run in " + DaysSince(lastRun) + " days", "Last run " + J.FormatDateTime(lastRun) + ".");
            }

            // VSS writers.
            var vssTable = new TableBlock("VSS writers with problems", new[] { "Writer", "State", "Last error" }, new[] { 3.0, 1.6, 2.6 });
            CheckResult vss = C("VSSWriters");
            string vssOut = J.Str(vss.First, "StandardOutput");
            if (vssOut.Length > 0)
            {
                var writers = Regex.Matches(vssOut, @"Writer name:\s*'([^']+)'.*?State:\s*\[(\d+)\]\s*([^\r\n]+).*?Last error:\s*([^\r\n]+)", RegexOptions.Singleline);
                int bad = 0;
                foreach (Match m in writers)
                {
                    string state = m.Groups[3].Value.Trim(), err = m.Groups[4].Value.Trim();
                    bool ok = m.Groups[2].Value == "1" && err.Equals("No error", StringComparison.OrdinalIgnoreCase);
                    if (ok) continue;
                    bad++;
                    vssTable.Add(m.Groups[1].Value, new Cell(state, Severity.Critical), err);
                }
                if (writers.Count > 0)
                {
                    kv.Add("VSS writers", writers.Count + " found, " + (bad == 0 ? "all stable" : bad + " with errors"));
                    if (bad > 0) Add("vss-writers", Severity.Critical, "Backups", J.Plural(bad, "VSS writer is", "VSS writers are") + " failing",
                        string.Join(", ", vssTable.Rows.Select(row => row[0].Text).Take(5).ToArray()) + ". Backups that rely on VSS may be incomplete; restart the related service or the server.");
                    else Add("vss-writers", Severity.Pass, "Backups", "All " + writers.Count + " VSS writers stable", "");
                }
            }

            CheckResult sc = C("ShadowCopies");
            if (sc.Ok) kv.Add("Shadow copies", sc.Data.Count.ToString(CultureInfo.InvariantCulture) + (sc.Data.Count > 0 ? ", newest " + J.FormatDateTime(sc.Data.Select(x => J.Date(x, "InstallDate")).Max()) : ""));

            EventFinding("BackupErrorDetails", "backup-events", "Backups", "backup-related error", "backup-related errors", "in the Application log in the last 30 days.", Severity.Warning, false);
            EventFinding("VSSErrorDetails", "vss-events", "Backups", "VSS / snapshot error", "VSS / snapshot errors", "in the System log in the last 30 days.", Severity.Warning, false);
            foreach (string name in r.CheckNames.Where(n => n.StartsWith("VeeamEventErrors:", StringComparison.Ordinal)).ToList())
                EventFinding(name, "veeam-" + name, "Backups", "Veeam error", "Veeam errors", "in " + name.Substring(17) + " in the last 30 days.", Severity.Warning, false);

            // Hyper-V.
            var vmTable = new TableBlock("Hyper-V virtual machines", new[] { "VM", "State", "Status", "Oldest checkpoint" }, new[] { 2.8, 1.1, 2.0, 2.0 });
            CheckResult hv = C("HyperVInventory");
            if (hv.Ok && hv.First != null)
            {
                var vms = J.List(J.Get(hv.First, "VMs"));
                a.HasHyperVVMs = vms.Count > 0;
                foreach (object vm in vms)
                {
                    string id = J.Str(vm, "Id"), name = J.Str(vm, "Name");
                    object cp = C("HyperVCheckpoints:" + id).First;
                    var cps = J.List(J.Get(cp, "Checkpoints"));
                    DateTime? oldest = cps.Select(x => J.Date(x, "CreationTime")).Where(d => d.HasValue).OrderBy(d => d).FirstOrDefault();
                    string cpText = cps.Count == 0 ? "None" : J.FormatDate(oldest) + " (" + cps.Count + ")";
                    Severity cpSev = oldest.HasValue && DaysSince(oldest) > 7 ? Severity.Warning : Severity.Pass;
                    if (cpSev == Severity.Warning)
                        Add("checkpoint-" + id, Severity.Warning, "Backups", "VM \"" + name + "\" has a checkpoint " + DaysSince(oldest) + " days old",
                            "Old checkpoints grow AVHDX files and slow the VM. Delete or merge them if no longer needed.");
                    string state = J.Str(vm, "State");
                    vmTable.Add(name, new Cell(state, state == "Running" ? Severity.Pass : Severity.Info), J.Str(vm, "Status"), cps.Count == 0 ? new Cell("None") : new Cell(cpText, cpSev));
                }
                foreach (object rep in C("HyperVReplication").Data)
                {
                    object h = J.Get(rep, "Health");
                    string ht = h is string ? (string)h : ((int)(J.Num(h) ?? 0) == 1 ? "Normal" : (int)(J.Num(h) ?? 0) == 2 ? "Warning" : (int)(J.Num(h) ?? 0) == 3 ? "Critical" : J.Str(h));
                    if (ht != "Normal" && ht.Length > 0)
                        Add("replica-" + J.Str(rep, "VMName"), ht == "Critical" ? Severity.Critical : Severity.Warning, "Backups",
                            "Hyper-V replication for \"" + J.Str(rep, "VMName") + "\" is " + ht, "Last replication " + J.FormatDateTime(J.Date(rep, "LastReplicationTime")) + ".");
                }
            }

            a.BackupEvidenceFound = products.Count > 0 || services.Count > 0 || wsbConfigured || relevantTasks > 0;
            if (!a.BackupEvidenceFound && C("BackupSoftware").Ok)
                Add("no-backup", Severity.Critical, "Backups", "No backup software or backup jobs found on this server",
                    "If the server is protected at the host or NAS level (agentless), confirm that in the backup console under Manual checks.");

            if (svcTable.Rows.Count > 0) sec.Blocks.Add(svcTable);
            if (taskTable.Rows.Count > 0) sec.Blocks.Add(taskTable);
            if (vssTable.Rows.Count > 0) sec.Blocks.Add(vssTable);
            if (vmTable.Rows.Count > 0) sec.Blocks.Add(vmTable);
            sec.Blocks.Add(new NoteBlock("Local evidence only. Backup success, retention and restorability are confirmed in the backup console (see Manual verification)."));
            a.Sections.Add(sec);
        }

        // ---------------------------------------------------------------- accounts

        private void Accounts()
        {
            var sec = new Section("Accounts and access");
            var admins = new TableBlock("Administrators group members", new[] { "Member", "Type", "Source" }, new[] { 4.0, 1.2, 1.6 });
            CheckResult adm = C("Administrators");
            foreach (object row in adm.Data)
            {
                var members = J.Get(row, "Members");
                if (members != null)
                {
                    foreach (object m in J.List(members)) admins.Add(J.Str(m, "SamAccountName").Length > 0 ? J.Str(m, "Name") + " (" + J.Str(m, "SamAccountName") + ")" : J.Str(m, "Name"), J.Str(m, "ObjectClass"), "Active Directory");
                }
                else
                {
                    object src = J.Get(row, "PrincipalSource");
                    string source = src is string ? (string)src : PrincipalSource(J.Num(src));
                    admins.Add(J.Str(row, "Name"), J.Str(row, "ObjectClass"), source);
                }
            }
            if (admins.Rows.Count > 8)
                Add("admin-count", Severity.Info, "Accounts", admins.Rows.Count + " members in the Administrators group", "Review that every member still needs full administrative rights.");

            var usersTable = new TableBlock("Local user accounts", new[] { "Account", "Enabled", "Last logon", "Password set" }, new[] { 2.6, 1.1, 1.8, 1.8 });
            CheckResult lu = C("LocalUsers");
            var stale = new List<string>();
            foreach (object u in lu.Data)
            {
                string name = J.Str(u, "Name"), sid = J.Str(u, "SID");
                bool enabled = J.Bool(u, "Enabled") ?? false;
                DateTime? lastLogon = J.Date(u, "LastLogon");
                usersTable.Add(name, new Cell(enabled ? "Yes" : "No", enabled ? Severity.Info : Severity.Unknown), lastLogon.HasValue ? J.FormatDate(lastLogon) : "Never", J.FormatDate(J.Date(u, "PasswordLastSet")));
                if (!enabled) continue;
                if (sid.EndsWith("-501")) Add("guest", Severity.Critical, "Accounts", "Guest account is enabled", "Disable the built-in Guest account.");
                else if (sid.EndsWith("-500")) Add("builtin-admin", Severity.Info, "Accounts", "Built-in Administrator account is enabled (" + name + ")", "Use named admin accounts; consider disabling or managing this account with LAPS.");
                if (J.Bool(u, "PasswordRequired") == false && !sid.EndsWith("-501"))
                    Add("nopassword-" + name, Severity.Warning, "Accounts", "Local account \"" + name + "\" does not require a password", "");
                if (!Regex.IsMatch(sid, "-(500|501|503|504)$") && (!lastLogon.HasValue || DaysSince(lastLogon) > 90)) stale.Add(name);
            }
            if (stale.Count > 0)
                Add("stale-local", Severity.Info, "Accounts", J.Plural(stale.Count, "enabled local account has", "enabled local accounts have") + " not logged on in 90+ days",
                    string.Join(", ", stale.ToArray()) + ". Disable accounts that are no longer needed.");

            sec.Blocks.Add(admins);
            if (usersTable.Rows.Count > 0) sec.Blocks.Add(usersTable);
            a.Sections.Add(sec);
        }

        private static string PrincipalSource(double? n)
        {
            switch ((int)(n ?? 0)) { case 1: return "Local"; case 2: return "Active Directory"; case 3: return "Entra ID"; case 4: return "Microsoft account"; default: return ""; }
        }

        // ---------------------------------------------------------------- events

        private void Events()
        {
            var sec = new Section("Event logs");
            var table = new TableBlock("Most frequent errors (last 30 days, recent-record sample)", new[] { "Log", "Source", "Event ID", "Count", "Last seen" }, new[] { 1.1, 3.0, 1.0, 0.8, 1.7 });
            foreach (string log in new[] { "System", "Application" })
            {
                CheckResult c = C(log + "Events");
                if (!c.Ok || c.First == null) continue;
                var events = J.List(J.Get(c.First, "Events"));
                int critical = events.Count(e => (J.Num(e, "Level") ?? 0) == 1);
                foreach (var g in events.GroupBy(e => J.Str(e, "ProviderName") + "|" + J.Str(e, "Id")).OrderByDescending(x => x.Count()).Take(6))
                {
                    var parts = g.Key.Split('|');
                    table.Add(log, parts[0], parts[1], g.Count().ToString(CultureInfo.InvariantCulture), J.FormatDateTime(g.Select(e => J.Date(e, "TimeCreated")).Max()));
                }
                if (critical > 0)
                    Add(log.ToLowerInvariant() + "-critical", Severity.Warning, "System", J.Plural(critical, "critical event", "critical events") + " in the " + log + " log",
                        "Sources: " + string.Join(", ", events.Where(e => (J.Num(e, "Level") ?? 0) == 1).Select(e => J.Str(e, "ProviderName") + " " + J.Str(e, "Id")).Distinct().Take(4).ToArray()) + ".");
            }
            table.EmptyText = "No error events in the sampled records.";
            sec.Blocks.Add(table);
            a.Sections.Add(sec);
        }

        // ---------------------------------------------------------------- coverage

        private void Coverage()
        {
            int gaps = 0;
            foreach (string name in r.CheckNames.OrderBy(n => n))
            {
                CheckResult c = C(name);
                if (c.Status == "Collected" || name == "ExternalEvidence") continue;
                // Expected gaps that say nothing about the server.
                if (Match(c.Error, "not applicable|Domain controller: local SAM")) continue;
                if (name == "Antivirus" && Match(c.Error, "Invalid namespace|SecurityCenter2")) continue;
                if (name == "LocalNATMappings" || name == "ServerRoles" && !Match(a.OsName, "Server")) continue;
                if (name.StartsWith("Hyper") && Match(c.Error, "Hyper-V.*(not|was not) (loaded|found|installed)|module")) continue;
                if (name.StartsWith("WindowsBackup") || name == "WbadminVersions")
                    if (Match(c.Error, "WindowsServerBackup|not recognized|module|No backup")) continue;
                gaps++;
                a.Coverage.Add(name, new Cell(c.Status, c.Status == "Partial" ? Severity.Warning : Severity.Unknown), J.Shorten(c.Error.Length > 0 ? c.Error : "No data returned.", 160));
            }
            if (gaps > 0)
                Add("coverage", Severity.Info, "Audit", J.Plural(gaps, "check", "checks") + " returned no or partial data",
                    "See Collection coverage at the end of the report. Missing data is not counted as a pass.");
        }
    }
}
