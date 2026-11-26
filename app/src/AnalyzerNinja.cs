using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace PolarniteAudit
{
    /// <summary>
    /// Rules for data pulled from NinjaOne (stored next to the report as .ninja.json):
    /// device details, organization (client name), open alerts, OS patches and antivirus.
    /// </summary>
    internal sealed partial class Analyzer
    {
        private void NinjaOne()
        {
            object n = r.Ninja;
            if (n == null) return;
            var sec = new Section("NinjaOne");
            DateTime? fetched = J.Date(n, "FetchedUtc");
            sec.Intro = "Pulled from NinjaOne" + (fetched.HasValue ? " on " + J.FormatDateTime(fetched.Value.ToLocalTime()) : "") + ".";
            if (J.Bool(n, "Matched") != true)
            {
                sec.Blocks.Add(new NoteBlock(J.Str(n, "MatchNote").Length > 0 ? J.Str(n, "MatchNote") : "This server was not found in NinjaOne."));
                Add("ninja-nomatch", Severity.Warning, "Monitoring", "Server not found in NinjaOne", J.Str(n, "MatchNote") + " Check that the NinjaOne agent is installed and approved.");
                a.Sections.Add(sec);
                return;
            }
            object dev = J.Get(n, "Device");
            object org = J.Get(n, "Organization");
            string orgName = J.Str(org, "name");
            if (orgName.Length == 0) orgName = J.Str(J.Get(dev, "references", "organization"), "name");
            if (orgName.Length > 0) { a.NinjaOrganization = orgName; a.Snapshot.Add("NinjaOne organization", orgName); }

            var kv = new KeyValueBlock();
            object refs = J.Get(n, "References") ?? J.Get(dev, "references");
            kv.Add("Device", J.Str(dev, "displayName").Length > 0 ? J.Str(dev, "displayName") : J.Str(dev, "systemName"));
            kv.Add("Matched by", J.Str(n, "MatchedBy"));
            kv.Add("Organization", orgName);
            string location = J.Str(n, "Location").Length > 0 ? J.Str(n, "Location") : J.Str(J.Get(refs, "location"), "name");
            string policy = J.Str(n, "Policy").Length > 0 ? J.Str(n, "Policy") : J.Str(J.Get(refs, "policy"), "name");
            kv.Add("Location", location);
            kv.Add("Policy", policy);
            bool offline = J.Bool(dev, "offline") == true;
            DateTime? lastContact = Ninja.Time(J.Get(dev, "lastContact"));
            kv.Add("Agent status", (offline ? "Offline" : "Online") + (lastContact.HasValue ? ", last contact " + J.FormatDateTime(lastContact) : ""));
            DateTime? boot = Ninja.Time(J.Get(dev, "os", "lastBootTime"));
            if (boot.HasValue) kv.Add("Last boot (NinjaOne)", J.FormatDateTime(boot));
            if (J.Bool(J.Get(dev, "os"), "needsReboot") == true) kv.Add("Reboot", "NinjaOne reports a reboot is needed");
            object warranty = J.Get(refs, "warranty");
            DateTime? warrantyEnd = Ninja.Time(J.Get(warranty, "endDate"));
            if (warrantyEnd.HasValue) kv.Add("Warranty ends", J.FormatDate(warrantyEnd));
            string maintenance = J.Str(J.Get(dev, "maintenance"), "status");
            if (maintenance.Length > 0) kv.Add("Maintenance mode", maintenance);
            sec.Blocks.Add(kv);

            if (offline || (lastContact.HasValue && (now - lastContact.Value).TotalHours > 24))
                Add("ninja-offline", Severity.Warning, "Monitoring", "NinjaOne shows this server " + (offline ? "offline" : "not checking in"),
                    "Last contact " + J.FormatDateTime(lastContact) + ". Check the NinjaOne agent service and its internet access.");
            if (warrantyEnd.HasValue && !a.IsVirtual)
            {
                int days = (int)Math.Floor((warrantyEnd.Value - now).TotalDays);
                if (days < 0) Add("ninja-warranty", Severity.Info, "Hardware", "Hardware warranty expired " + J.FormatDate(warrantyEnd), "Parts and on-site support are no longer covered. Consider extending it or planning replacement.");
                else if (days <= 90) Add("ninja-warranty", Severity.Warning, "Hardware", "Hardware warranty ends in " + J.Plural(days, "day", "days"), "Ends " + J.FormatDate(warrantyEnd) + ". Renew it or plan replacement.");
            }

            // Open alerts (conditions).
            var alerts = J.List(J.Get(n, "Alerts"));
            var alertTable = new TableBlock("Open NinjaOne alerts", new[] { "Alert", "Severity", "Since" }, new[] { 5.0, 1.2, 1.6 });
            alertTable.EmptyText = "No open alerts.";
            foreach (object al in alerts)
            {
                string sev = J.Str(al, "severity").ToUpperInvariant();
                if (sev == "NONE") sev = "";
                // conditionName is the readable alert name; message has the detail (subject is often empty).
                string title = J.Str(al, "conditionName").Length > 0 ? J.Str(al, "conditionName") : J.Str(al, "subject").Length > 0 ? J.Str(al, "subject") : J.Str(al, "message");
                string message = J.Str(al, "message");
                if (message.Length > 0 && message != title) title += ": " + message;
                alertTable.Add(J.Shorten(title, 160), new Cell(sev.Length > 0 ? sev : "Alert", sev == "CRITICAL" || sev == "MAJOR" ? Severity.Critical : sev == "MODERATE" ? Severity.Warning : Severity.Info),
                    J.FormatDateTime(Ninja.Time(J.Get(al, "createTime"))));
            }
            sec.Blocks.Add(alertTable);
            if (alerts.Count > 0)
            {
                bool severe = alerts.Any(al => Regex.IsMatch(J.Str(al, "severity"), "^(CRITICAL|MAJOR)$", RegexOptions.IgnoreCase));
                Add("ninja-alerts", severe ? Severity.Critical : Severity.Warning, "Monitoring", J.Plural(alerts.Count, "open NinjaOne alert", "open NinjaOne alerts"),
                    string.Join("; ", alertTable.Rows.Take(4).Select(row => row[0].Text).ToArray()) + ". Resolve or reset them in NinjaOne.");
            }

            // OS patches as NinjaOne sees them.
            var patches = J.List(J.Get(n, "OsPatches"));
            var failed = patches.Where(p => J.Str(p, "status").ToUpperInvariant() == "FAILED").ToList();
            var pending = patches.Where(p => Regex.IsMatch(J.Str(p, "status"), "^(APPROVED|PENDING|MANUAL)$", RegexOptions.IgnoreCase)).ToList();
            if (J.Get(n, "OsPatches") != null)
            {
                var patchTable = new TableBlock("NinjaOne OS patches not installed", new[] { "Patch", "Status", "Severity" }, new[] { 5.0, 1.2, 1.4 });
                patchTable.EmptyText = "None pending or failed.";
                foreach (object p in failed.Concat(pending).Take(25))
                {
                    string st = J.Str(p, "status").ToUpperInvariant();
                    patchTable.Add(J.Shorten(J.Str(p, "name") + (J.Str(p, "kbNumber").Length > 0 && J.Str(p, "name").IndexOf(J.Str(p, "kbNumber"), StringComparison.OrdinalIgnoreCase) < 0 ? " (" + J.Str(p, "kbNumber") + ")" : ""), 150),
                        new Cell(st, st == "FAILED" ? Severity.Warning : Severity.Info), J.Str(p, "severity"));
                }
                sec.Blocks.Add(patchTable);
                if (failed.Count > 0)
                    Add("ninja-patch-failed", Severity.Warning, "Patching", J.Plural(failed.Count, "patch failed", "patches failed") + " to install (NinjaOne)",
                        string.Join("; ", failed.Take(4).Select(p => J.Str(p, "name")).ToArray()) + ". Check the patch log in NinjaOne.");
                if (pending.Count > 0)
                    Add("ninja-patch-pending", Severity.Info, "Patching", J.Plural(pending.Count, "patch is", "patches are") + " waiting to install (NinjaOne)", "They install at the next patch window or need manual approval.");
            }

            // Antivirus managed through NinjaOne (for example Bitdefender).
            var av = J.List(J.Get(n, "AntivirusStatus"));
            var threats = J.List(J.Get(n, "AntivirusThreats")).Where(t => { DateTime? when = Ninja.Time(J.Get(t, "timestamp")); return !when.HasValue || (now - when.Value).TotalDays <= 30; }).ToList();
            if (av.Count > 0 || threats.Count > 0)
            {
                var avTable = new TableBlock("Antivirus (NinjaOne)", new[] { "Product", "State", "Definitions", "Reported" }, new[] { 2.6, 1.4, 1.6, 1.6 });
                foreach (object s in av)
                {
                    string state = J.Str(s, "productState"), defs = J.Str(s, "definitionStatus");
                    bool on = Regex.IsMatch(state, "^(ON|ENABLED|RUNNING)$", RegexOptions.IgnoreCase);
                    bool current = defs.Length == 0 || Regex.IsMatch(defs, "UP.?TO.?DATE|CURRENT", RegexOptions.IgnoreCase);
                    avTable.Add(J.Str(s, "productName"), new Cell(state, on ? Severity.Pass : Severity.Critical), new Cell(defs, current ? Severity.Pass : Severity.Warning), J.FormatDateTime(Ninja.Time(J.Get(s, "timestamp"))));
                    if (!on) Add("ninja-av-off-" + J.Str(s, "productName"), Severity.Critical, "Security", J.Str(s, "productName") + " is " + state.ToLowerInvariant() + " (NinjaOne)", "Turn real-time protection back on in NinjaOne.");
                    else if (!current) Add("ninja-av-defs-" + J.Str(s, "productName"), Severity.Warning, "Security", J.Str(s, "productName") + " definitions are " + defs.ToLowerInvariant().Replace('_', ' ') + " (NinjaOne)", "Check the antivirus update source.");
                }
                sec.Blocks.Add(avTable);
                var threatTable = new TableBlock("Antivirus threats in the last 30 days (NinjaOne)", new[] { "Threat", "Status", "When" }, new[] { 4.6, 1.6, 1.6 });
                threatTable.EmptyText = "No threats reported.";
                foreach (object t in threats)
                    threatTable.Add(J.Shorten(J.Str(t, "name"), 120), new Cell(J.Str(t, "status"), NinjaThreatOpen(t) ? Severity.Critical : Severity.Pass), J.FormatDateTime(Ninja.Time(J.Get(t, "timestamp"))));
                sec.Blocks.Add(threatTable);
                var open = threats.Where(NinjaThreatOpen).ToList();
                if (open.Count > 0)
                    Add("ninja-av-threats", Severity.Critical, "Security", J.Plural(open.Count, "antivirus threat is", "antivirus threats are") + " not resolved (NinjaOne)",
                        string.Join("; ", open.Take(4).Select(t => J.Str(t, "name") + " (" + J.Str(t, "status").ToLowerInvariant() + ")").ToArray()) + ".");
                ninjaAvLine = av.Count > 0
                    ? string.Join(", ", av.Select(s => J.Str(s, "productName") + " " + J.Str(s, "productState").ToLowerInvariant()).ToArray()) + "; " +
                      (open.Count > 0 ? open.Count + " unresolved threat(s)" : threats.Count > 0 ? threats.Count + " threat(s) in 30 days, all resolved" : "no threats in 30 days") + " (NinjaOne)"
                    : null;
                ninjaAvOk = open.Count == 0 && av.All(s => Regex.IsMatch(J.Str(s, "productState"), "^(ON|ENABLED|RUNNING)$", RegexOptions.IgnoreCase));
            }

            foreach (object e in J.List(J.Get(n, "Errors")))
                sec.Blocks.Add(new NoteBlock("Could not read " + J.Str(e) + "."));

            // RMM manual check, answered from NinjaOne.
            var issues = new List<string>();
            if (offline) issues.Add("device offline");
            if (alerts.Count > 0) issues.Add(J.Plural(alerts.Count, "open alert", "open alerts"));
            if (failed.Count > 0) issues.Add(J.Plural(failed.Count, "failed patch", "failed patches"));
            Auto("rmm_health", issues.Count > 0 ? ManualCatalog.Issue : ManualCatalog.Pass,
                "NinjaOne: " + (issues.Count > 0 ? string.Join(", ", issues.ToArray()) : "online, no open alerts, no failed patches") +
                (policy.Length > 0 ? "; policy " + policy : "") + ".");
            a.Sections.Add(sec);
        }

        private string ninjaAvLine;
        private bool ninjaAvOk;

        private static bool NinjaThreatOpen(object t)
        {
            string s = J.Str(t, "status");
            return s.Length == 0 || !Regex.IsMatch(s, "QUARANTIN|REMOVED|DELETED|CLEAN|BLOCKED|RESOLVED|RESTORED|IGNORED", RegexOptions.IgnoreCase);
        }
    }
}
