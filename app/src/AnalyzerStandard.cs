using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace PolarniteAudit
{
    /// <summary>
    /// Collector 1.13 rules (antivirus detections, backup jobs, certificates, activation,
    /// LAPS, hardening, key services, hardware, Active Directory, internet exposure),
    /// automatic answers for manual checks, and the month-over-month comparison.
    /// </summary>
    internal sealed partial class Analyzer
    {
        private sealed class JobSummary
        {
            public string Product, Job, LastResult;
            public DateTime? LastRun, LastSuccess;
            public int Failed, Runs;
        }

        private readonly List<JobSummary> veeamJobs = new List<JobSummary>();
        private int defenderUnresolved = -1, defenderRemediated;
        private readonly List<string> defenderNames = new List<string>();
        private bool hardwareToolFound;
        private readonly List<string> hardwareProblems = new List<string>();
        private int hardwareEventErrors = -1;
        private object exposure;

        private Section SectionNamed(string title)
        {
            Section s = a.Sections.FirstOrDefault(x => x.Title == title);
            if (s == null) { s = new Section(title); a.Sections.Add(s); }
            return s;
        }

        private void StandardChecks()
        {
            DefenderDetections();
            BackupJobs();
            AgentActivity();
            Certificates();
            var hardening = new TableBlock("Hardening and key services", new[] { "Control", "Status", "Detail" }, new[] { 2.6, 1.4, 4.0 });
            Activation(hardening);
            Laps(hardening);
            Hardening(hardening);
            KeyServices(hardening);
            if (hardening.Rows.Count > 0) SectionNamed("Security").Blocks.Insert(1, hardening);
            Hardware();
            ActiveDirectory();
            Exposure();
            PlatformChecks();
        }

        // ------------------------------------------------------------ antivirus

        private void DefenderDetections()
        {
            CheckResult c = C("DefenderThreats");
            if (!c.Ok) return;
            var detections = c.Data.Where(d => J.Str(d, "RecordType") == "Detection").ToList();
            var unresolved = new List<string>();
            var remediated = new List<string>();
            var table = new TableBlock("Antivirus detections (last 30 days)", new[] { "Threat", "Detected", "Status" }, new[] { 4.0, 1.6, 1.6 });
            foreach (object d in detections)
            {
                int status = (int)(J.Num(d, "ThreatStatusID") ?? 0);
                string name = J.Str(d, "ThreatName");
                if (name.Length == 0) name = "Threat " + J.Str(d, "ThreatID");
                string label; Severity sev;
                switch (status)
                {
                    case 2: label = "Cleaned"; sev = Severity.Pass; break;
                    case 3: label = "Quarantined"; sev = Severity.Pass; break;
                    case 4: label = "Removed"; sev = Severity.Pass; break;
                    case 6: label = "Blocked"; sev = Severity.Pass; break;
                    case 5: label = "Allowed"; sev = Severity.Warning; break;
                    case 1: label = "Active"; sev = Severity.Critical; break;
                    default: label = status >= 100 ? "Action failed" : "Unknown"; sev = status >= 100 ? Severity.Critical : Severity.Warning; break;
                }
                if (sev == Severity.Pass) remediated.Add(name); else unresolved.Add(name + " (" + label.ToLowerInvariant() + ")");
                table.Add(name, J.FormatDateTime(J.Date(d, "InitialDetectionTime")), new Cell(label, sev));
            }
            defenderUnresolved = unresolved.Count;
            defenderRemediated = remediated.Count;
            defenderNames.AddRange(detections.Select(d => J.Str(d, "ThreatName")).Where(n => n.Length > 0).Distinct());
            if (unresolved.Count > 0)
                Add("av-unresolved", Severity.Critical, "Security", J.Plural(unresolved.Count, "antivirus detection is", "antivirus detections are") + " not resolved",
                    string.Join("; ", unresolved.Distinct().Take(5).ToArray()) + ". Investigate in Defender / the EDR console and run a full scan.");
            else if (remediated.Count > 0)
                Add("av-remediated", Severity.Info, "Security", J.Plural(remediated.Count, "threat was", "threats were") + " detected and remediated in the last 30 days",
                    string.Join("; ", remediated.Distinct().Take(5).ToArray()) + ". Check how it arrived.");
            else if (otherAntivirus.Count == 0)
                Add("av-clean", Severity.Pass, "Security", "No antivirus detections in the last 30 days", "");
            if (table.Rows.Count > 0) SectionNamed("Security").Blocks.Add(table);
        }

        // ------------------------------------------------------------ backup jobs

        private void BackupJobs()
        {
            CheckResult c = C("BackupJobResults");
            if (!c.Ok) return;
            var sessions = c.Data.Where(d => J.Str(d, "RecordType") == "Session").ToList();
            foreach (var g in sessions.GroupBy(d => J.Str(d, "Product") + "|" + J.Str(d, "Job")))
            {
                var ordered = g.OrderByDescending(d => J.Date(d, "EndTime") ?? DateTime.MinValue).ToList();
                var job = new JobSummary
                {
                    Product = J.Str(ordered[0], "Product"), Job = J.Str(ordered[0], "Job"), LastResult = J.Str(ordered[0], "Result"),
                    LastRun = J.Date(ordered[0], "EndTime"), Runs = ordered.Count,
                    Failed = ordered.Count(d => J.Str(d, "Result") == "Failed"),
                    LastSuccess = ordered.Where(d => J.Str(d, "Result") != "Failed").Select(d => J.Date(d, "EndTime")).FirstOrDefault()
                };
                veeamJobs.Add(job);
            }
            if (veeamJobs.Count == 0) return;
            var table = new TableBlock("Backup jobs (Veeam, last 30 days)", new[] { "Job", "Last run", "Result", "Last success", "Failed runs" }, new[] { 2.8, 1.6, 1.1, 1.6, 0.9 });
            bool allGood = true;
            foreach (JobSummary j in veeamJobs.OrderBy(x => x.Job))
            {
                Severity sev = j.LastResult == "Failed" ? Severity.Critical : j.LastResult == "Warning" ? Severity.Warning : Severity.Pass;
                table.Add(j.Job, J.FormatDateTime(j.LastRun), new Cell(j.LastResult, sev), J.FormatDateTime(j.LastSuccess), j.Failed.ToString(CultureInfo.InvariantCulture));
                int age = DaysSince(j.LastSuccess);
                if (j.LastResult == "Failed")
                {
                    allGood = false;
                    Add("veeam-" + j.Job, Severity.Critical, "Backups", "Veeam job \"" + j.Job + "\" failed on its last run",
                        "Last run " + J.FormatDateTime(j.LastRun) + "; last success " + (j.LastSuccess.HasValue ? J.FormatDateTime(j.LastSuccess) + " (" + age + " days ago)" : "none in 30 days") + ".");
                }
                else if (j.LastSuccess.HasValue && age > 2)
                {
                    allGood = false;
                    Add("veeam-age-" + j.Job, Severity.Critical, "Backups", "Veeam job \"" + j.Job + "\" has not succeeded in " + age + " days", "Last success " + J.FormatDateTime(j.LastSuccess) + ".");
                }
                else if (j.LastResult == "Warning")
                {
                    allGood = false;
                    Add("veeam-warn-" + j.Job, Severity.Warning, "Backups", "Veeam job \"" + j.Job + "\" finished with warnings", "Last run " + J.FormatDateTime(j.LastRun) + ". Review the job session in Veeam.");
                }
            }
            if (allGood) Add("veeam-ok", Severity.Pass, "Backups", "All " + J.Plural(veeamJobs.Count, "Veeam job", "Veeam jobs") + " succeeded on their last run", "");
            SectionNamed("Backups").Blocks.Insert(1, table);
        }

        // ------------------------------------------------------------ agents

        private void AgentActivity()
        {
            CheckResult c = C("AgentActivity");
            foreach (string agent in new[] { "NinjaRMM", "Huntress" })
            {
                object row = c.Data.Where(d => J.Str(d, "Agent") == agent).OrderByDescending(d => J.Date(d, "LastWriteTime") ?? DateTime.MinValue).FirstOrDefault();
                string pattern = agent == "NinjaRMM" ? "Ninja" : "Huntress";
                var services = C("AgentServices").Data.Where(s => J.Str(s, "Name").IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0 || J.Str(s, "DisplayName").IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0).ToList();
                if (services.Count == 0 && row == null) continue;
                var parts = new List<string>();
                if (services.Count > 0)
                    parts.Add(string.Join(", ", services.Select(s => J.Str(s, "DisplayName") + " " + J.Str(s, "State").ToLowerInvariant()).ToArray()));
                DateTime? last = row == null ? null : J.Date(row, "LastWriteTime");
                if (last.HasValue)
                {
                    double hours = (now - last.Value).TotalHours;
                    parts.Add("agent log updated " + (hours < 1 ? Math.Max(1, (int)(hours * 60)) + " min ago" : hours < 48 ? (int)hours + " h ago" : (int)(hours / 24) + " days ago"));
                    if (hours > 24 && services.Any(s => J.Str(s, "State") == "Running"))
                        Add("agent-stale-" + agent, Severity.Warning, "Security", agent + " agent log has not been written in " + (int)(hours / 24) + " days",
                            "The service is running but the agent may be stuck or unable to reach its cloud. Check the device in the " + agent + " console.");
                }
                string id = agent == "NinjaRMM" ? "rmm_health" : "edr_health";
                a.AutoHints[id] = string.Join("; ", parts.ToArray()) + ". Console alerts still need checking.";
            }
        }

        // ------------------------------------------------------------ certificates

        private void Certificates()
        {
            CheckResult c = C("CertificateExpiry");
            if (!c.Ok) return;
            var table = new TableBlock("Certificates expiring within 60 days", new[] { "Certificate", "Store", "Expires", "Status" }, new[] { 4.2, 1.2, 1.4, 1.3 });
            table.EmptyText = "No certificates expire within 60 days.";
            int problems = 0;
            foreach (object cert in c.Data)
            {
                bool selfSigned = J.Bool(cert, "SelfSigned") == true, rdp = J.Bool(cert, "UsedForRdp") == true;
                if (selfSigned || J.Bool(cert, "HasPrivateKey") != true) continue; // self-signed RDP/WinRM certificates renew themselves
                DateTime? notAfter = J.Date(cert, "NotAfter");
                if (!notAfter.HasValue) continue;
                int days = (int)Math.Floor((notAfter.Value - now).TotalDays);
                if (days < -90) continue;
                string subject = Regex.Replace(J.Str(cert, "Subject"), @"^CN=([^,]+).*$", "$1");
                if (rdp) subject += " (RDP)";
                Severity sev = days < 0 ? Severity.Warning : days <= 14 ? Severity.Critical : days <= 30 ? Severity.Warning : Severity.Info;
                string status = days < 0 ? "Expired" : days + " days";
                table.Add(subject, J.Str(cert, "Store"), J.FormatDate(notAfter), new Cell(status, sev));
                if (sev == Severity.Info) continue;
                problems++;
                if (days < 0)
                    Add("cert-" + J.Str(cert, "Thumbprint"), Severity.Warning, "Security", "Certificate \"" + subject + "\" expired " + J.FormatDate(notAfter), "Remove it if it is no longer used, or replace it. Issuer: " + J.Str(cert, "Issuer") + ".");
                else
                    Add("cert-" + J.Str(cert, "Thumbprint"), sev, "Security", "Certificate \"" + subject + "\" expires in " + J.Plural(days, "day", "days"),
                        "Expires " + J.FormatDate(notAfter) + ". Renew it and update any bindings (IIS, RDP, VPN, RD Gateway). Issuer: " + J.Str(cert, "Issuer") + ".");
            }
            if (problems == 0) Add("certs-ok", Severity.Pass, "Security", "No certificates expiring within 30 days", "");
            SectionNamed("Security").Blocks.Add(table);
        }

        // ------------------------------------------------------------ hardening

        private void Activation(TableBlock t)
        {
            CheckResult c = C("Activation");
            if (!c.Ok || c.First == null) return;
            object os = c.Data.FirstOrDefault(x => !Match(J.Str(x, "Name") + " " + J.Str(x, "Description"), @"\bESU\b")) ?? c.First;
            foreach (object esu in c.Data.Where(x => x != os && Match(J.Str(x, "Name") + " " + J.Str(x, "Description"), @"\bESU\b")))
                t.Add("Extended Security Updates", new Cell((J.Num(esu, "LicenseStatus") ?? 0) == 1 ? "Activated" : "Not activated", (J.Num(esu, "LicenseStatus") ?? 0) == 1 ? Severity.Pass : Severity.Warning), J.Str(esu, "Name"));
            int status = (int)(J.Num(os, "LicenseStatus") ?? -1);
            string[] names = { "Unlicensed", "Licensed", "Out-of-box grace", "Out-of-tolerance grace", "Non-genuine grace", "Notification", "Extended grace" };
            string text = status >= 0 && status < names.Length ? names[status] : "Unknown";
            t.Add("Windows activation", new Cell(status == 1 ? "Activated" : text, status == 1 ? Severity.Pass : Severity.Warning), J.Str(os, "Description"));
            if (status == 1) Add("activation", Severity.Pass, "System", "Windows is activated", "");
            else Add("activation", Severity.Warning, "System", "Windows is not activated (" + text + ")",
                "Activate Windows (KMS/AVMA/MAK) before the grace period ends. Unactivated servers show notifications and may lose functionality.");
        }

        private void Laps(TableBlock t)
        {
            CheckResult c = C("LAPS");
            if (!c.Ok || c.First == null || a.IsDomainController || !a.PartOfDomain) return;
            bool legacy = J.Bool(c.First, "LegacyCseInstalled") == true && J.Bool(c.First, "LegacyPolicyEnabled") == true;
            int backup = (int)(J.Num(c.First, "WindowsLapsBackupDirectory") ?? 0);
            bool on = legacy || backup == 1 || backup == 2;
            t.Add("LAPS (local admin password)", new Cell(on ? "Configured" : "Not configured", on ? Severity.Pass : Severity.Info),
                legacy ? "Legacy Microsoft LAPS" : backup == 2 ? "Windows LAPS to Active Directory" : backup == 1 ? "Windows LAPS to Entra ID" : "");
            if (on) Add("laps", Severity.Pass, "Accounts", "LAPS manages the local administrator password", "");
            else Add("laps", Severity.Info, "Accounts", "LAPS is not configured", "The local Administrator password is not rotated automatically. Windows LAPS is built into Windows 10/11 and Server 2019 and later (April 2023 update).");
        }

        private void Hardening(TableBlock t)
        {
            CheckResult c = C("SecurityHardening");
            if (!c.Ok || c.First == null) return;
            object h = c.First;
            int build;
            int.TryParse(J.Str(C("System").First, "Build"), out build);
            var protocols = J.List(J.Get(h, "SchannelServer"));
            Func<string, bool?> disabled = name =>
            {
                object p = protocols.FirstOrDefault(x => J.Str(x, "Protocol") == name);
                if (p == null) return null;
                double? en = J.Num(p, "Enabled"), dbd = J.Num(p, "DisabledByDefault");
                if (en.HasValue && en.Value == 0) return true;
                if (dbd.HasValue && dbd.Value == 1) return true;
                if (en.HasValue && en.Value != 0) return false;
                return null; // OS default
            };
            bool? ssl3 = disabled("SSL 3.0"), tls10 = disabled("TLS 1.0"), tls11 = disabled("TLS 1.1");
            bool legacyOn = (tls10 != true || tls11 != true) && !(tls10 == null && tls11 == null && build >= 26100);
            t.Add("TLS 1.0 / 1.1 (server)", new Cell(legacyOn ? "Enabled" : "Disabled", legacyOn ? Severity.Info : Severity.Pass), tls10 == null ? "Operating-system default" : "Set in registry");
            if (legacyOn) Add("tls-legacy", Severity.Info, "Security", "TLS 1.0 / 1.1 are still enabled", "Disable them once applications on this server support TLS 1.2 (SQL, RDP and older line-of-business software can depend on them).");
            if (ssl3 == false || (ssl3 == null && build > 0 && build <= 9600))
            {
                t.Add("SSL 3.0 (server)", new Cell("Enabled", Severity.Warning), "");
                Add("ssl3", Severity.Warning, "Security", "SSL 3.0 is enabled", "SSL 3.0 is broken (POODLE). Disable it in SCHANNEL.");
            }

            double? llmnr = J.Num(h, "LLMNREnableMulticast");
            var netbiosOn = J.List(J.Get(h, "NetbiosOptions")).Where(n => (J.Num(n, "TcpipNetbiosOptions") ?? 0) != 2).ToList();
            bool llmnrOn = !(llmnr.HasValue && llmnr.Value == 0);
            t.Add("LLMNR", new Cell(llmnrOn ? "Enabled" : "Disabled", llmnrOn ? Severity.Info : Severity.Pass), llmnrOn ? "No policy turning it off" : "Disabled by policy");
            t.Add("NetBIOS over TCP/IP", new Cell(netbiosOn.Count > 0 ? "Enabled" : "Disabled", netbiosOn.Count > 0 ? Severity.Info : Severity.Pass), netbiosOn.Count > 0 ? J.Plural(netbiosOn.Count, "adapter", "adapters") : "");
            if (llmnrOn || netbiosOn.Count > 0)
                Add("name-poisoning", Severity.Info, "Security", "LLMNR / NetBIOS name resolution is enabled",
                    "Attackers on the network can answer these broadcasts to capture password hashes. Disable LLMNR by GPO and NetBIOS over TCP/IP where nothing needs it.");

            double? wdigest = J.Num(h, "WDigestUseLogonCredential");
            if (wdigest.HasValue && wdigest.Value == 1)
            {
                t.Add("WDigest", new Cell("Clear-text", Severity.Critical), "UseLogonCredential = 1");
                Add("wdigest", Severity.Critical, "Security", "WDigest keeps passwords in memory in clear text", "Set HKLM\\...\\WDigest\\UseLogonCredential to 0 and restart. This is a common credential-theft setting.");
            }
            else t.Add("WDigest", new Cell("Off", Severity.Pass), "");

            double? lm = J.Num(h, "LmCompatibilityLevel"), noLmHash = J.Num(h, "NoLMHash");
            int level = lm.HasValue ? (int)lm.Value : 3;
            t.Add("NTLM level (LmCompatibilityLevel)", new Cell(level.ToString(CultureInfo.InvariantCulture), level < 3 ? Severity.Warning : Severity.Pass), lm.HasValue ? "" : "Operating-system default (3)");
            if (level < 3) Add("ntlmv1", Severity.Warning, "Security", "LM / NTLMv1 authentication is allowed (level " + level + ")", "Set \"Network security: LAN Manager authentication level\" to send NTLMv2 only (5) after checking old devices.");
            if (noLmHash.HasValue && noLmHash.Value == 0) Add("lmhash", Severity.Warning, "Security", "LM password hashes are stored", "Enable \"Do not store LAN Manager hash value\".");

            double? ppl = J.Num(h, "RunAsPPL");
            bool lsa = ppl.HasValue && (ppl.Value == 1 || ppl.Value == 2);
            t.Add("LSA protection (RunAsPPL)", new Cell(lsa ? "On" : "Off", lsa ? Severity.Pass : Severity.Info), "");
            if (!lsa) Add("lsa-ppl", Severity.Info, "Security", "LSA protection is off", "Running LSASS as a protected process makes credential dumping harder. Test drivers/plug-ins first.");

            if (C("ServerRoles").Data.Any(r => J.Str(r, "Name") == "PowerShell-V2" || J.Str(r, "Name") == "MicrosoftWindowsPowerShellV2Root"))
            {
                t.Add("PowerShell 2.0", new Cell("Installed", Severity.Warning), "");
                Add("psv2", Severity.Warning, "Security", "PowerShell 2.0 is installed", "PowerShell 2.0 bypasses script-block logging and AMSI. Remove the PowerShell-V2 feature.");
            }

            object au = J.Get(h, "AutoUpdatePolicy");
            string wsus = J.Str(au, "WUServer");
            bool noAuto = (J.Num(au, "NoAutoUpdate") ?? 0) == 1;
            t.Add("Update source", new Cell(wsus.Length > 0 ? "WSUS" : "Microsoft", Severity.Info), wsus.Length > 0 ? wsus : (noAuto ? "Automatic updates off by policy (RMM-managed?)" : ""));
        }

        private void KeyServices(TableBlock t)
        {
            CheckResult c = C("KeyServices");
            if (!c.Ok) return;
            Func<string, object> svc = n => c.Data.FirstOrDefault(s => string.Equals(J.Str(s, "Name"), n, StringComparison.OrdinalIgnoreCase));
            Func<object, bool> running = s => s != null && J.Str(s, "State") == "Running";
            object spooler = svc("Spooler");
            if (a.IsDomainController && running(spooler))
            {
                t.Add("Print Spooler on a domain controller", new Cell("Running", Severity.Warning), "");
                Add("dc-spooler", Severity.Warning, "Security", "Print Spooler is running on a domain controller", "Disable it unless this DC is a print server (PrintNightmare / printer-bug coercion).");
            }
            foreach (var pair in new[] { new[] { "MpsSvc", "Windows Firewall service" }, new[] { "EventLog", "Windows Event Log service" }, new[] { "Schedule", "Task Scheduler service" } })
            {
                object s = svc(pair[0]);
                if (s != null && !running(s))
                    Add("svc-" + pair[0], Severity.Critical, "System", pair[1] + " is not running", "State " + J.Str(s, "State") + ", startup " + J.Str(s, "StartMode") + ".");
            }
            object wu = svc("wuauserv");
            if (wu != null && J.Str(wu, "StartMode") == "Disabled")
            {
                t.Add("Windows Update service", new Cell("Disabled", Severity.Warning), "");
                Add("wuauserv-disabled", Severity.Warning, "Patching", "Windows Update service is disabled", "Patching through RMM or WSUS still needs this service. Set it to Manual.");
            }
            object time = svc("W32Time");
            if (time != null && !running(time)) Add("w32time-stopped", Severity.Warning, "System", "Windows Time service is not running", "Domain authentication depends on accurate time.");
            object remote = svc("RemoteRegistry");
            if (running(remote)) t.Add("Remote Registry", new Cell("Running", Severity.Info), "Disable if not needed");
        }

        // ------------------------------------------------------------ hardware

        private void Hardware()
        {
            CheckResult c = C("HardwareVendorHealth");
            var table = new TableBlock("Hardware health (vendor tools)", new[] { "Component", "Tool", "Status" }, new[] { 4.0, 1.6, 1.4 });
            foreach (object section in c.Data.Where(d => J.Str(d, "RecordType") == "Section"))
            {
                hardwareToolFound = true;
                string tool = J.Str(section, "Tool");
                foreach (object item in J.List(J.Get(section, "Items")))
                {
                    string component = J.Str(item, "Component");
                    if (component.Length == 0) component = "Virtual disk " + J.Str(item, "ID") + (J.Str(item, "Name").Length > 0 ? " (" + J.Str(item, "Name") + ", " + J.Str(item, "Layout") + ")" : "");
                    string status = J.Str(item, "Status");
                    string state = J.Str(item, "State");
                    if (state.Length > 0 && state != "Ready" && state != "Online") status = status + " / " + state;
                    Severity sev = Regex.IsMatch(status, @"^(Ok|OK)( / )?$") ? Severity.Pass
                        : Regex.IsMatch(status, "Non-Critical|Warning|Rebuild|Predictive", RegexOptions.IgnoreCase) ? Severity.Warning
                        : Regex.IsMatch(status, "Not Applicable|Unknown", RegexOptions.IgnoreCase) ? Severity.Unknown : Severity.Critical;
                    if (status.StartsWith("Ok", StringComparison.OrdinalIgnoreCase) && status.Contains("/")) sev = Severity.Warning; // OK but degraded state
                    table.Add(component, tool, new Cell(status, sev));
                    if (sev == Severity.Critical || sev == Severity.Warning) hardwareProblems.Add(component + ": " + status);
                }
            }
            hardwareEventErrors = -1;
            CheckResult ev = C("HardwareEvents");
            if (ev.Ok && ev.First != null)
                hardwareEventErrors = EventFinding("HardwareEvents", "hardware-events", "Hardware", "hardware/controller error", "hardware/controller errors", "in the System log in the last 30 days.", Severity.Warning, false);
            if (hardwareToolFound)
            {
                if (hardwareProblems.Count > 0)
                    Add("hardware", Severity.Critical, "Hardware", J.Plural(hardwareProblems.Count, "hardware component reports", "hardware components report") + " a problem",
                        string.Join("; ", hardwareProblems.Take(6).ToArray()) + ". Check iDRAC/iLO and open a vendor case if a part has failed.");
                else Add("hardware", Severity.Pass, "Hardware", "Hardware reports healthy (" + string.Join(", ", c.Data.Where(d => J.Str(d, "RecordType") == "Section").Select(d => J.Str(d, "Tool")).Distinct().ToArray()) + ")", "");
                SectionNamed("Storage").Blocks.Add(table);
            }
        }

        // ------------------------------------------------------------ Active Directory

        private void ActiveDirectory()
        {
            CheckResult hy = C("ADHygiene");
            CheckResult dcdiag = C("DCDiag"), repl = C("ReplicationSummary");
            if (!hy.Ok && !dcdiag.Ok && !repl.Ok) return;
            var sec = new Section("Active Directory");
            var kv = new KeyValueBlock();
            sec.Blocks.Add(kv);
            if (hy.Ok && hy.First != null)
            {
                object h = hy.First;
                DateTime? krb = J.Date(h, "KrbtgtPasswordLastSet");
                int krbAge = DaysSince(krb);
                kv.Add("Enabled users / computers", J.Str(h, "EnabledUsers") + " / " + J.Str(h, "EnabledComputers"));
                kv.Add("krbtgt password set", krb.HasValue ? J.FormatDate(krb) + " (" + krbAge + " days ago)" : "Unknown");
                bool? recycle = J.Bool(h, "RecycleBinEnabled");
                kv.Add("AD Recycle Bin", recycle == true ? "Enabled" : recycle == false ? "Not enabled" : "Unknown");
                if (krb.HasValue && krbAge > 180)
                    Add("krbtgt", Severity.Warning, "Accounts", "krbtgt password is " + krbAge + " days old",
                        "Reset it twice (with replication time between) using Microsoft's New-KrbtgtKeys script. Old krbtgt keys extend golden-ticket risk.");
                if (recycle == false)
                    Add("ad-recycle", Severity.Warning, "Accounts", "AD Recycle Bin is not enabled", "Deleted users, groups and OUs can't be restored with their attributes. Enable it (forest level 2008 R2+); it can't be turned off later.");
                int staleUsers = (int)(J.Num(h, "StaleUsers") ?? 0), staleComputers = (int)(J.Num(h, "StaleComputers") ?? 0);
                int never = (int)(J.Num(h, "PasswordNeverExpires") ?? 0), oldOs = (int)(J.Num(h, "UnsupportedOsComputers") ?? 0);
                kv.Add("Stale accounts (90+ days)", staleUsers + " users, " + staleComputers + " computers");
                kv.Add("Passwords never expire", never + " enabled users");
                if (staleUsers > 0)
                    Add("stale-users", staleUsers > 10 ? Severity.Warning : Severity.Info, "Accounts", J.Plural(staleUsers, "enabled user has", "enabled users have") + " not signed in for 90+ days",
                        string.Join(", ", J.List(J.Get(h, "StaleUserSample")).Take(8).Select(u => J.Str(u, "SamAccountName")).ToArray()) + (staleUsers > 8 ? ", …" : "") + ". Disable leavers' accounts.");
                if (staleComputers > 0)
                    Add("stale-computers", Severity.Info, "Accounts", J.Plural(staleComputers, "enabled computer has", "enabled computers have") + " not signed in for 90+ days",
                        string.Join(", ", J.List(J.Get(h, "StaleComputerSample")).Take(8).Select(u => J.Str(u, "Name")).ToArray()) + (staleComputers > 8 ? ", …" : "") + ".");
                if (never > 0)
                    Add("pwd-never-expires", Severity.Info, "Accounts", J.Plural(never, "enabled user has", "enabled users have") + " a password that never expires",
                        string.Join(", ", J.List(J.Get(h, "PasswordNeverExpiresSample")).Take(8).Select(x => J.Str(x)).ToArray()) + (never > 8 ? ", …" : "") + ". Expected for some service accounts; review the rest.");
                if (oldOs > 0)
                {
                    var t = new TableBlock("Computers on unsupported Windows", new[] { "Computer", "Operating system" }, new[] { 2.0, 4.0 });
                    foreach (object x in J.List(J.Get(h, "UnsupportedOsSample"))) t.Add(J.Str(x, "Name"), J.Str(x, "OperatingSystem"));
                    sec.Blocks.Add(t);
                    Add("unsupported-os-computers", Severity.Warning, "Lifecycle", J.Plural(oldOs, "domain computer runs", "domain computers run") + " an unsupported Windows version",
                        string.Join(", ", J.List(J.Get(h, "UnsupportedOsSample")).Take(6).Select(x => J.Str(x, "Name") + " (" + J.Str(x, "OperatingSystem") + ")").ToArray()) + ".");
                }
            }
            if (dcdiag.Ok && dcdiag.First != null)
            {
                string output = J.Str(dcdiag.First, "StandardOutput");
                var failed = Regex.Matches(output, @"failed test\s+(\S+)", RegexOptions.IgnoreCase).Cast<Match>().Select(m => m.Groups[1].Value).Distinct().ToList();
                kv.Add("dcdiag", failed.Count == 0 ? "All tests passed" : "Failed: " + string.Join(", ", failed.ToArray()));
                if (failed.Count > 0)
                    Add("dcdiag", Severity.Warning, "System", "dcdiag reports " + J.Plural(failed.Count, "failed test", "failed tests"), string.Join(", ", failed.ToArray()) + ". Run dcdiag /v on the DC for details.");
                else if (J.Bool(dcdiag.First, "ReaderTimeLimitReached") != true) Add("dcdiag", Severity.Pass, "System", "dcdiag tests passed", "");
            }
            if (repl.Ok && repl.First != null)
            {
                string output = J.Str(repl.First, "StandardOutput");
                var failing = new List<string>();
                foreach (Match m in Regex.Matches(output, @"^\s*(\S+)\s+.*?\s(\d+)\s*/\s*(\d+)\s+\d+", RegexOptions.Multiline))
                    if (int.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture) > 0) failing.Add(m.Groups[1].Value);
                bool hasTable = Regex.IsMatch(output, @"fails/total", RegexOptions.IgnoreCase);
                if (hasTable) kv.Add("AD replication", failing.Count == 0 ? "No failures" : "Failures: " + string.Join(", ", failing.Distinct().ToArray()));
                if (failing.Count > 0)
                    Add("replication", Severity.Critical, "System", "Active Directory replication is failing", "Partners with failures: " + string.Join(", ", failing.Distinct().ToArray()) + ". Run repadmin /showrepl for errors.");
                else if (hasTable) Add("replication", Severity.Pass, "System", "AD replication healthy", "");
            }
            a.Sections.Add(sec);
        }

        // ------------------------------------------------------------ exposure

        private void Exposure()
        {
            CheckResult c = C("ExternalExposure");
            if (!c.Ok || c.First == null) return;
            exposure = c.First;
            var risky = new Dictionary<int, string> { { 21, "FTP" }, { 22, "SSH" }, { 23, "Telnet" }, { 135, "RPC" }, { 139, "NetBIOS" }, { 445, "SMB" }, { 1433, "SQL Server" }, { 3306, "MySQL" }, { 3389, "RDP" }, { 5900, "VNC" }, { 5985, "WinRM" }, { 5986, "WinRM" } };
            var ports = J.List(J.Get(exposure, "Ports")).Select(p => (int)(J.Num(p) ?? 0)).Where(p => p > 0).Distinct().OrderBy(p => p).ToList();
            var vulns = J.List(J.Get(exposure, "Vulns")).Select(v => J.Str(v)).ToList();
            string ip = J.Str(exposure, "PublicIP");
            var sec = new Section("Internet exposure");
            var kv = new KeyValueBlock();
            kv.Add("Public IP", ip);
            kv.Add("Open ports seen", ports.Count == 0 ? "None recorded" : string.Join(", ", ports.Select(p => risky.ContainsKey(p) ? p + " (" + risky[p] + ")" : p.ToString(CultureInfo.InvariantCulture)).ToArray()));
            if (vulns.Count > 0) kv.Add("Known CVEs listed", string.Join(", ", vulns.Take(12).ToArray()) + (vulns.Count > 12 ? ", …" : ""));
            kv.Add("Source", J.Str(exposure, "Source"));
            sec.Blocks.Add(kv);
            sec.Blocks.Add(new NoteBlock("Passive data for the public IP this server uses to reach the internet. A shared NAT address can include other devices at the site."));
            a.Sections.Add(sec);
            var bad = ports.Where(risky.ContainsKey).ToList();
            if (bad.Count > 0)
                Add("exposure-ports", Severity.Critical, "Security", "Risky services are reachable from the internet on " + ip,
                    string.Join(", ", bad.Select(p => risky[p] + " (" + p + ")").ToArray()) + ". Close them at the firewall or put them behind a VPN.");
            else Add("exposure-ports", Severity.Pass, "Security", "No risky ports open on the public IP", ports.Count > 0 ? "Open: " + string.Join(", ", ports.Select(p => p.ToString(CultureInfo.InvariantCulture)).ToArray()) + "." : "");
            if (vulns.Count > 0)
                Add("exposure-cves", Severity.Warning, "Security", J.Plural(vulns.Count, "known vulnerability is", "known vulnerabilities are") + " listed for the public IP",
                    string.Join(", ", vulns.Take(6).ToArray()) + ". Check the firewall/VPN firmware and any published services.");
        }

        // ------------------------------------------------------------ automatic answers

        private void Auto(string id, string status, string note)
        {
            a.AutoAnswers[id] = new ManualAnswer { Status = status, Notes = ManualAnswer.AutoPrefix + note, AutoSet = true };
        }

        private void AutoVerify()
        {
            // Antivirus: only when Defender is the active antivirus.
            if (defenderUnresolved >= 0 && otherAntivirus.Count == 0 && C("Defender").Ok)
            {
                if (defenderUnresolved > 0) Auto("av_detections", ManualCatalog.Issue, defenderUnresolved + " unresolved Microsoft Defender detection(s) in 30 days.");
                else if (defenderRemediated > 0) Auto("av_detections", ManualCatalog.Pass, defenderRemediated + " Defender detection(s) in 30 days, all remediated (" + string.Join(", ", defenderNames.Take(3).ToArray()) + ").");
                else Auto("av_detections", ManualCatalog.Pass, "no Microsoft Defender detections in the last 30 days.");
            }

            // Antivirus managed through NinjaOne (for example Bitdefender), when Defender did not answer it.
            if (ninjaAvLine != null && !a.AutoAnswers.ContainsKey("av_detections"))
                Auto("av_detections", ninjaAvOk ? ManualCatalog.Pass : ManualCatalog.Issue, ninjaAvLine + ".");

            // Backups: Veeam job events and Windows Server Backup.
            var lines = new List<string>();
            bool backupOk = true, failuresOpen = false;
            int failedRuns = 0;
            foreach (JobSummary j in veeamJobs)
            {
                lines.Add("Veeam \"" + j.Job + "\" last " + j.LastResult.ToLowerInvariant() + " " + J.FormatDateTime(j.LastRun) + (j.LastResult == "Failed" ? ", last success " + J.FormatDateTime(j.LastSuccess) : ""));
                if (!j.LastSuccess.HasValue || DaysSince(j.LastSuccess) > 2) backupOk = false;
                if (j.LastResult == "Failed") failuresOpen = true;
                failedRuns += j.Failed;
            }
            if (wsbScheduled || wsbLastSuccess.HasValue)
            {
                lines.Add("Windows Server Backup last success " + J.FormatDateTime(wsbLastSuccess));
                if (!wsbLastSuccess.HasValue || DaysSince(wsbLastSuccess) > 2) backupOk = false;
            }
            if (abbLine != null)
            {
                lines.Add(abbLine);
                if (!abbHealthy) backupOk = false;
            }
            if (lines.Count > 0)
            {
                Auto("backup_last_success", backupOk ? ManualCatalog.Pass : ManualCatalog.Issue, string.Join("; ", lines.ToArray()) + ".");
                var open = new List<string>();
                if (failuresOpen) open.Add("Veeam " + string.Join(", ", veeamJobs.Where(j => j.LastResult == "Failed").Select(j => "\"" + j.Job + "\"").ToArray()) + " failed on its last run");
                if (abbFailureOpen) open.Add("Synology Active Backup's last run failed");
                if (veeamJobs.Count > 0 || abbLine != null)
                    Auto("backup_failures", open.Count > 0 ? ManualCatalog.Issue : ManualCatalog.Pass, open.Count > 0
                        ? string.Join("; ", open.ToArray()) + "."
                        : (veeamJobs.Count > 0 && failedRuns > 0 ? failedRuns + " failed Veeam run(s) in 30 days, each followed by a successful run." : "the latest run of every backup job succeeded."));
            }

            // Hardware: vendor tools, or virtual machine.
            if (hardwareToolFound)
            {
                if (hardwareProblems.Count > 0 || hardwareEventErrors > 0)
                    Auto("hardware_health", ManualCatalog.Issue, string.Join("; ", hardwareProblems.Take(4).ToArray()) + (hardwareEventErrors > 0 ? (hardwareProblems.Count > 0 ? "; " : "") + hardwareEventErrors + " hardware error event(s)" : "") + ".");
                else Auto("hardware_health", ManualCatalog.Pass, "vendor tools report all components OK and no hardware error events in 30 days.");
            }
            else if (a.IsVirtual) Auto("hardware_health", ManualCatalog.NotApplicable, "virtual machine; check host health in the hypervisor console.");

            // Internet exposure.
            if (exposure != null)
            {
                Finding f = a.Findings.FirstOrDefault(x => x.Key == "exposure-ports");
                if (f != null)
                    Auto("exposure", f.Severity == Severity.Pass ? ManualCatalog.Pass : ManualCatalog.Issue,
                        "Shodan InternetDB for " + J.Str(exposure, "PublicIP") + ": " + (f.Severity == Severity.Pass ? "no risky ports. " + f.Detail : f.Detail));
            }
        }

        // ------------------------------------------------------------ month over month

        private static HashSet<string> Names(IEnumerable<string> values)
        {
            return new HashSet<string>(values.Where(v => !string.IsNullOrWhiteSpace(v)), StringComparer.OrdinalIgnoreCase);
        }

        private static IEnumerable<string> AdminNames(AuditReport r)
        {
            foreach (object row in r.Check("Administrators").Data)
            {
                object members = J.Get(row, "Members");
                if (members != null) foreach (object m in J.List(members)) yield return J.Str(m, "Name");
                else yield return J.Str(row, "Name");
            }
        }

        private void CompareWith(AuditReport prevReport, AuditAnalysis prev)
        {
            if (prevReport.AuditTime >= r.AuditTime) return;
            a.PreviousAuditTime = prevReport.AuditTime;
            a.PreviousCritical = prev.Count(Severity.Critical);
            a.PreviousWarning = prev.Count(Severity.Warning);
            var sec = new Section("Changes since the last audit");
            sec.Intro = "Compared with the audit submitted " + J.FormatDate(prevReport.AuditTime) + ".";
            var kv = new KeyValueBlock(); // filled at the end, once this comparison's own findings exist
            sec.Blocks.Add(kv);

            // New and resolved issues.
            var before = new Dictionary<string, Finding>();
            foreach (Finding f in prev.Findings.Where(f => f.Severity <= Severity.Warning)) before[f.Key] = f;
            var nowKeys = new HashSet<string>(a.Findings.Where(f => f.Severity <= Severity.Warning).Select(f => f.Key));
            foreach (Finding f in a.Findings.Where(f => f.Severity <= Severity.Warning)) f.IsNew = !before.ContainsKey(f.Key);
            foreach (var kvp in before) if (!nowKeys.Contains(kvp.Key)) a.Resolved.Add(kvp.Value.Title);
            if (a.Resolved.Count > 0)
            {
                var t = new TableBlock("Resolved since the last audit", new[] { "Finding" }, new[] { 1.0 });
                foreach (string title in a.Resolved) t.Add(new Cell(title));
                sec.Blocks.Add(t);
            }

            // Disk growth forecast.
            double days = Math.Max(1, (r.AuditTime - prevReport.AuditTime).TotalDays);
            var prevDisks = prevReport.Check("Disks").Data.ToDictionary(d => J.Str(d, "DeviceID"), d => J.Num(d, "FreeGB"));
            var disk = new TableBlock("Disk space trend", new[] { "Drive", "Free last audit", "Free now", "Change", "Forecast" }, new[] { 0.8, 1.3, 1.2, 1.2, 2.2 });
            foreach (object d in r.Check("Disks").Data)
            {
                string id = J.Str(d, "DeviceID");
                double? freeNow = J.Num(d, "FreeGB"), freeBefore;
                if (!freeNow.HasValue || !prevDisks.TryGetValue(id, out freeBefore) || !freeBefore.HasValue) continue;
                double change = freeNow.Value - freeBefore.Value;
                string forecast = "Stable";
                Severity sev = Severity.Pass;
                if (change < -0.5)
                {
                    double perDay = -change / days;
                    int full = (int)Math.Floor(freeNow.Value / perDay);
                    forecast = full > 365 ? "Over a year at this rate" : "Full in about " + J.Plural(full, "day", "days");
                    sev = full < 30 ? Severity.Critical : full < 90 ? Severity.Warning : Severity.Pass;
                    if (sev != Severity.Pass)
                        Add("disk-forecast-" + id, sev, "Storage", "Drive " + id + " will fill in about " + J.Plural(full, "day", "days") + " at the current rate",
                            "Free space fell from " + Gb(freeBefore) + " to " + Gb(freeNow) + " in " + (int)days + " days (" + (perDay).ToString("0.0", CultureInfo.InvariantCulture) + " GB/day). Plan cleanup or expansion.").IsNew = true;
                }
                disk.Add(id, Gb(freeBefore), Gb(freeNow), (change >= 0 ? "+" : "") + change.ToString("0.0", CultureInfo.InvariantCulture) + " GB", new Cell(forecast, sev));
            }
            if (disk.Rows.Count > 0) sec.Blocks.Add(disk);

            // Administrators.
            var adminBefore = Names(AdminNames(prevReport));
            var adminNow = Names(AdminNames(r));
            var changes = new TableBlock("Other changes", new[] { "Change", "Item" }, new[] { 1.8, 5.0 });
            foreach (string n in adminNow.Where(x => !adminBefore.Contains(x)).OrderBy(x => x))
            {
                changes.Add(new Cell("Admin added", Severity.Warning), n);
                Add("admin-added-" + n, Severity.Warning, "Accounts", "New member of Administrators: " + n, "Added since the last audit. Confirm the change was approved.").IsNew = true;
            }
            foreach (string n in adminBefore.Where(x => !adminNow.Contains(x)).OrderBy(x => x)) changes.Add(new Cell("Admin removed", Severity.Info), n);

            // Software and services.
            if (prevReport.Check("Software").Ok && r.Check("Software").Ok)
            {
                var softBefore = Names(prevReport.Check("Software").Data.Select(s => J.Str(s, "DisplayName")));
                var softNow = Names(r.Check("Software").Data.Select(s => J.Str(s, "DisplayName")));
                var installed = softNow.Where(x => !softBefore.Contains(x)).OrderBy(x => x).ToList();
                var removed = softBefore.Where(x => !softNow.Contains(x)).OrderBy(x => x).ToList();
                foreach (string s in installed.Take(25)) changes.Add(new Cell("Installed", Severity.Info), s);
                foreach (string s in removed.Take(15)) changes.Add(new Cell("Removed", Severity.Unknown), s);
                var remoteTools = installed.Where(x => Regex.IsMatch(x, "TeamViewer|AnyDesk|Splashtop|RustDesk|VNC|LogMeIn|ScreenConnect|ConnectWise Control|Atera|Kaseya", RegexOptions.IgnoreCase)).ToList();
                if (remoteTools.Count > 0)
                    Add("new-remote-tool", Severity.Warning, "Security", "New remote access software installed", string.Join(", ", remoteTools.ToArray()) + ". Confirm it is authorised.").IsNew = true;
            }
            if (prevReport.Check("ListeningPorts").Ok && r.Check("ListeningPorts").Ok)
            {
                Func<AuditReport, HashSet<string>> ports = rep => Names(rep.Check("ListeningPorts").Data.Select(p => J.Num(p, "LocalPort")).Where(p => p.HasValue && p.Value < 49152).Select(p => p.Value.ToString(CultureInfo.InvariantCulture)));
                var before2 = ports(prevReport);
                foreach (string p in ports(r).Where(x => !before2.Contains(x)).OrderBy(x => int.Parse(x, CultureInfo.InvariantCulture))) changes.Add(new Cell("New listening port", Severity.Info), p);
            }
            if (changes.Rows.Count > 0) sec.Blocks.Add(changes);
            kv.Add("Critical findings", a.Count(Severity.Critical) + " (was " + a.PreviousCritical + ")");
            kv.Add("Warnings", a.Count(Severity.Warning) + " (was " + a.PreviousWarning + ")");
            kv.Add("New since last audit", a.Findings.Count(f => f.IsNew).ToString(CultureInfo.InvariantCulture));
            kv.Add("Resolved since last audit", a.Resolved.Count.ToString(CultureInfo.InvariantCulture));
            a.Sections.Insert(0, sec);
        }
    }
}
