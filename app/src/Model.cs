using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace PolarniteAudit
{
    internal enum Severity { Critical = 0, Warning = 1, Info = 2, Pass = 3, Unknown = 4, Accepted = 5 }

    internal static class Sev
    {
        public static string Label(Severity s)
        {
            switch (s)
            {
                case Severity.Critical: return "Critical";
                case Severity.Warning: return "Warning";
                case Severity.Info: return "Best practice";
                case Severity.Pass: return "Pass";
                case Severity.Accepted: return "Accepted";
                default: return "Unknown";
            }
        }
    }

    internal sealed class Finding
    {
        public string Key;
        public Severity Severity;
        public string Area;
        public string Title;
        public string Detail;
        public string TechNote = "";
        public bool IsNew;   // not a critical/warning finding in the previous audit
        public Severity? OriginalSeverity;   // set when a technician override changed the rating
        public string OverrideBy = "", OverrideReason = "";

        /// <summary>"Rated Accepted by J. Smith (was Critical): reason" for reports; empty when not overridden.</summary>
        public string OverrideText
        {
            get
            {
                if (!OriginalSeverity.HasValue) return "";
                return "Rated " + Sev.Label(Severity) + (OverrideBy.Length > 0 ? " by " + OverrideBy : " by the technician") + " (was " + Sev.Label(OriginalSeverity.Value) + ")" +
                       (OverrideReason.Trim().Length > 0 ? ": " + OverrideReason.Trim() : ".");
            }
        }
    }

    /// <summary>One table cell. When Chip is set the renderers draw a colored pill.</summary>
    internal sealed class Cell
    {
        public string Text;
        public Severity? Chip;
        public Cell(string text) { Text = text ?? ""; }
        public Cell(string text, Severity chip) { Text = text ?? ""; Chip = chip; }
        public static implicit operator Cell(string s) { return new Cell(s); }
    }

    internal abstract class Block { }

    internal sealed class KeyValueBlock : Block
    {
        public readonly List<KeyValuePair<string, string>> Items = new List<KeyValuePair<string, string>>();
        public void Add(string k, string v) { if (!string.IsNullOrEmpty(v)) Items.Add(new KeyValuePair<string, string>(k, v)); }
    }

    internal sealed class TableBlock : Block
    {
        public string Caption;
        public string[] Columns;
        public double[] Widths; // relative
        public readonly List<Cell[]> Rows = new List<Cell[]>();
        public string EmptyText = "None found.";
        public TableBlock(string caption, string[] columns, double[] widths) { Caption = caption; Columns = columns; Widths = widths; }
        public void Add(params Cell[] row) { Rows.Add(row); }
    }

    internal sealed class BarItem
    {
        public string Label;
        public string Right;
        public double UsedFraction;
        public Severity Severity;
    }

    internal sealed class BarBlock : Block
    {
        public readonly List<BarItem> Items = new List<BarItem>();
    }

    internal sealed class NoteBlock : Block
    {
        public string Text;
        public NoteBlock(string text) { Text = text; }
    }

    internal sealed class Section
    {
        public string Title;
        public string Intro = "";
        public readonly List<Block> Blocks = new List<Block>();
        public Section(string title) { Title = title; }
    }

    internal sealed class CheckResult
    {
        public string Name;
        public string Status = "Missing";
        public string Error = "";
        public List<object> Data = new List<object>();
        public bool Ok { get { return Status == "Collected" || Status == "Partial"; } }
        public object First { get { return Data.Count > 0 ? Data[0] : null; } }
    }

    /// <summary>The collector's JSON report (final or -PARTIAL checkpoint).</summary>
    internal sealed class AuditReport
    {
        public string Path;
        public object Root;
        public bool Incomplete;
        public bool Elevated;
        public string SchemaVersion;
        public DateTime? StartedAt;
        public DateTime? CompletedAt;
        public bool DeepAudit;
        public object Ninja;   // NinjaOne data saved next to the report (.ninja.json), or null

        public static AuditReport Load(string path)
        {
            string text = File.ReadAllText(path, Encoding.UTF8);
            object root = J.Parse(text);
            if (J.Dict(root) == null || J.Dict(J.Get(root, "Checks")) == null)
                throw new InvalidDataException("This file is not an audit collector JSON report (no Checks section).");
            var r = new AuditReport();
            r.Path = path;
            r.Root = root;
            r.Incomplete = J.Bool(root, "Incomplete") ?? false;
            r.Elevated = J.Bool(root, "Elevated") ?? false;
            r.SchemaVersion = J.Str(root, "SchemaVersion");
            r.StartedAt = J.Date(root, "StartedAt");
            r.CompletedAt = J.Date(root, "CompletedAt") ?? J.Date(root, "SavedAt");
            r.DeepAudit = J.Bool(root, "DeepAuditRequested") ?? false;
            string ninja = PolarniteAudit.Ninja.SidecarPath(path);
            if (File.Exists(ninja))
            {
                try { r.Ninja = J.Parse(File.ReadAllText(ninja, Encoding.UTF8)); }
                catch (Exception ex) { Log.Write("Could not read " + ninja + ": " + ex.Message); }
            }
            return r;
        }

        public IEnumerable<string> CheckNames
        {
            get
            {
                var d = J.Dict(J.Get(Root, "Checks"));
                return d == null ? Enumerable.Empty<string>() : d.Keys;
            }
        }

        public CheckResult Check(string name)
        {
            var c = new CheckResult { Name = name };
            object raw = J.Get(Root, "Checks", name);
            if (raw == null) return c;
            c.Status = J.Str(raw, "Status");
            c.Error = J.Str(raw, "Error");
            c.Data = J.List(J.Get(raw, "Data"));
            return c;
        }

        public DateTime AuditTime
        {
            get { return CompletedAt ?? StartedAt ?? File.GetLastWriteTime(Path); }
        }
    }

    internal sealed class AuditAnalysis
    {
        public string ServerName = "";
        public string DomainName = "";
        public bool PartOfDomain;
        public string EntraTenant = "";
        public string TenantSource = "";   // "Entra join" or "Microsoft 365 sign-in"
        public string NinjaOrganization = "";

        /// <summary>Client name for the ticket: the NinjaOne organization, else the Entra tenant.</summary>
        public string ClientName { get { return NinjaOrganization.Length > 0 ? NinjaOrganization : EntraTenant; } }
        public string ClientNameSource { get { return NinjaOrganization.Length > 0 ? "NinjaOne" : TenantSource; } }
        public string OsName = "";
        public string OsSupportText = "";
        public Severity OsSupportSeverity = Severity.Unknown;
        public bool IsDomainController;
        public bool IsVirtual;
        public bool IsClientOs;   // Windows 10/11 used as a server
        public bool HasHyperVVMs;
        public bool OsNeedsEntitlementCheck;
        public bool BackupEvidenceFound;
        public DateTime AuditTime;
        public bool Elevated;
        public bool Incomplete;
        public string CollectorVersion = "";
        public readonly KeyValueBlock Snapshot = new KeyValueBlock();
        public readonly List<Finding> Findings = new List<Finding>();
        public readonly List<Section> Sections = new List<Section>();
        public readonly Dictionary<string, ManualAnswer> AutoAnswers = new Dictionary<string, ManualAnswer>();
        public readonly Dictionary<string, string> AutoHints = new Dictionary<string, string>();
        public DateTime? PreviousAuditTime;
        public int PreviousCritical = -1, PreviousWarning = -1;
        public readonly List<string> Resolved = new List<string>();
        public readonly TableBlock Coverage = new TableBlock("Checks that returned no or partial data",
            new[] { "Check", "Status", "Reason" }, new[] { 2.2, 1.45, 5.0 });

        public int Count(Severity s) { return Findings.Count(f => f.Severity == s); }

        public string DefaultTenant
        {
            get
            {
                if (!string.IsNullOrEmpty(ClientName)) return ClientName;
                if (PartOfDomain && !string.IsNullOrEmpty(DomainName)) return DomainName;
                return "";
            }
        }

        public string MonthLabel { get { return AuditTime.ToString("MMMM yyyy", CultureInfo.InvariantCulture); } }
        public string MonthKey { get { return AuditTime.ToString("yyyy-MM", CultureInfo.InvariantCulture); } }
    }

    /// <summary>A check the collector cannot perform; a technician answers it in the app.</summary>
    internal sealed class ManualItemDef
    {
        public string Id;
        public string Area;
        public string Title;
        public string Guidance;
        public bool Required;
        public Func<AuditAnalysis, bool> AppliesTo;
    }

    internal static class ManualCatalog
    {
        public const string NotChecked = "Not checked";
        public const string Pass = "Pass";
        public const string Issue = "Issue found";
        public const string NotApplicable = "N/A";
        public static readonly string[] Statuses = { NotChecked, Pass, Issue, NotApplicable };

        public static readonly List<ManualItemDef> Items = new List<ManualItemDef>
        {
            new ManualItemDef { Id = "backup_last_success", Area = "Backups", Required = true,
                Title = "Last successful backup confirmed in backup console",
                Guidance = "Product, job name and date/time of the last successful backup." },
            new ManualItemDef { Id = "backup_failures", Area = "Backups", Required = true,
                Title = "No unresolved backup failures in the last 30 days",
                Guidance = "Note any failed or warning jobs and what was done." },
            new ManualItemDef { Id = "backup_offsite", Area = "Backups", Required = true,
                Title = "Offsite / cloud copy is current",
                Guidance = "Replication or cloud copy target and its last successful date." },
            new ManualItemDef { Id = "hyperv_coverage", Area = "Backups", Required = true,
                Title = "Every Hyper-V VM is included in a backup job",
                Guidance = "List any VMs excluded on purpose.", AppliesTo = a => a.HasHyperVVMs },
            new ManualItemDef { Id = "rmm_health", Area = "Monitoring", Required = true,
                Title = "RMM (NinjaOne): device online, no open alerts, patch policy applied",
                Guidance = "Note any open alerts or patch policy exceptions." },
            new ManualItemDef { Id = "edr_health", Area = "Security", Required = true,
                Title = "EDR (Huntress): agent healthy, no open incidents",
                Guidance = "Note any open incidents or remediation steps." },
            new ManualItemDef { Id = "av_detections", Area = "Security", Required = true,
                Title = "Antivirus: no unresolved detections",
                Guidance = "Console used and any detections reviewed." },
            new ManualItemDef { Id = "hardware_health", Area = "Hardware", Required = false,
                Title = "Hardware / host health: iDRAC/iLO, RAID, UPS or hypervisor alerts reviewed",
                Guidance = "Mark N/A for cloud VMs if not applicable." },
            new ManualItemDef { Id = "os_entitlement", Area = "Lifecycle", Required = true,
                Title = "OS support / ESU entitlement or replacement plan confirmed",
                Guidance = "This OS is out of support or ends within 12 months.", AppliesTo = a => a.OsNeedsEntitlementCheck },
            new ManualItemDef { Id = "mfa_remote", Area = "Access", Required = false,
                Title = "Remote access (VPN, RD Gateway, RMM remote) requires MFA",
                Guidance = "System and policy checked." },
            new ManualItemDef { Id = "exposure", Area = "Access", Required = false,
                Title = "No unexpected internet exposure (RDP/SMB not published at the firewall)",
                Guidance = "Firewall/NAT rules reviewed." },
        };

        public static List<ManualItemDef> For(AuditAnalysis a)
        {
            return Items.Where(i => i.AppliesTo == null || a == null || i.AppliesTo(a)).ToList();
        }
    }

    internal sealed class ManualAnswer
    {
        public const string AutoPrefix = "Auto-verified: ";
        public const string HintPrefix = "Local evidence: ";
        public string Status = ManualCatalog.NotChecked;
        public string Notes = "";
        public bool AutoSet;   // set by the app from collected evidence; cleared when a technician edits it
    }

    /// <summary>
    /// Everything a technician edits for one month's audit of this server. Saved
    /// under ProgramData so a scheduled (SYSTEM) run and the GUI share it.
    /// </summary>
    internal sealed class DraftState
    {
        public string Status = "Draft";   // Draft | Submitted
        public string Source = "Manual";  // Manual | Scheduled
        public string ReportPath = "";
        public string MonthKey = "";
        public string CreatedAt = "";
        public string Tenant = "";
        public string TenantSource = "";   // "Technician" once someone types the name; otherwise it follows the Entra tenant
        public string Technician = "";
        public string ServerPurpose = "";
        public string Summary = "";
        public string SubmittedAt = "";
        public string SubmittedTo = "";
        public string PdfPath = "";
        public Dictionary<string, ManualAnswer> Manual = new Dictionary<string, ManualAnswer>();
        public Dictionary<string, string> FindingNotes = new Dictionary<string, string>();

        public bool IsSubmitted { get { return Status == "Submitted"; } }

        public ManualAnswer Answer(string id)
        {
            ManualAnswer a;
            if (!Manual.TryGetValue(id, out a)) { a = new ManualAnswer(); Manual[id] = a; }
            return a;
        }

        public Dictionary<string, object> ToDict()
        {
            var manual = new Dictionary<string, object>();
            foreach (var kv in Manual)
                manual[kv.Key] = new Dictionary<string, object> { { "Status", kv.Value.Status }, { "Notes", kv.Value.Notes }, { "AutoSet", kv.Value.AutoSet } };
            var notes = new Dictionary<string, object>();
            foreach (var kv in FindingNotes) if (!string.IsNullOrWhiteSpace(kv.Value)) notes[kv.Key] = kv.Value;
            return new Dictionary<string, object>
            {
                { "Status", Status }, { "Source", Source }, { "ReportPath", ReportPath }, { "MonthKey", MonthKey },
                { "CreatedAt", CreatedAt }, { "Tenant", Tenant }, { "TenantSource", TenantSource }, { "Technician", Technician },
                { "ServerPurpose", ServerPurpose }, { "Summary", Summary }, { "SubmittedAt", SubmittedAt },
                { "SubmittedTo", SubmittedTo }, { "PdfPath", PdfPath }, { "Manual", manual }, { "FindingNotes", notes }
            };
        }

        public static DraftState FromDict(object o)
        {
            var d = new DraftState();
            if (J.Dict(o) == null) return d;
            d.Status = Or(J.Str(o, "Status"), "Draft");
            d.Source = Or(J.Str(o, "Source"), "Manual");
            d.ReportPath = J.Str(o, "ReportPath");
            d.MonthKey = J.Str(o, "MonthKey");
            d.CreatedAt = J.Str(o, "CreatedAt");
            d.Tenant = J.Str(o, "Tenant");
            d.TenantSource = J.Str(o, "TenantSource");
            d.Technician = J.Str(o, "Technician");
            d.ServerPurpose = J.Str(o, "ServerPurpose");
            d.Summary = J.Str(o, "Summary");
            d.SubmittedAt = J.Str(o, "SubmittedAt");
            d.SubmittedTo = J.Str(o, "SubmittedTo");
            d.PdfPath = J.Str(o, "PdfPath");
            var manual = J.Dict(J.Get(o, "Manual"));
            if (manual != null)
                foreach (var kv in manual)
                    d.Manual[kv.Key] = new ManualAnswer { Status = Or(J.Str(kv.Value, "Status"), ManualCatalog.NotChecked), Notes = J.Str(kv.Value, "Notes"), AutoSet = J.Bool(kv.Value, "AutoSet") ?? false };
            var notes = J.Dict(J.Get(o, "FindingNotes"));
            if (notes != null) foreach (var kv in notes) d.FindingNotes[kv.Key] = J.Str(kv.Value);
            return d;
        }

        private static string Or(string a, string b) { return string.IsNullOrEmpty(a) ? b : a; }

        /// <summary>
        /// Applies answers derived from collected evidence. A technician's own answer always wins;
        /// an earlier automatic answer is refreshed, or cleared when the evidence is gone.
        /// </summary>
        public void ApplyAuto(AuditAnalysis a)
        {
            // The client name follows the Entra tenant unless a technician typed one.
            if (TenantSource != "Technician" && !string.IsNullOrEmpty(a.ClientName)) { Tenant = a.ClientName; TenantSource = a.ClientNameSource; }
            foreach (ManualItemDef item in ManualCatalog.Items)
            {
                ManualAnswer ans = Answer(item.Id);
                ManualAnswer auto;
                if (a.AutoAnswers.TryGetValue(item.Id, out auto))
                {
                    if (ans.Status == ManualCatalog.NotChecked || ans.AutoSet)
                    {
                        ans.Status = auto.Status;
                        ans.Notes = auto.Notes;
                        ans.AutoSet = true;
                    }
                }
                else if (ans.AutoSet)
                {
                    ans.Status = ManualCatalog.NotChecked;
                    ans.Notes = "";
                    ans.AutoSet = false;
                }
                string hint;
                bool hintable = ans.Status == ManualCatalog.NotChecked && !ans.AutoSet &&
                    (string.IsNullOrWhiteSpace(ans.Notes) || ans.Notes.StartsWith(ManualAnswer.HintPrefix, StringComparison.Ordinal));
                if (hintable)
                    ans.Notes = a.AutoHints.TryGetValue(item.Id, out hint) ? ManualAnswer.HintPrefix + hint : (ans.Notes.StartsWith(ManualAnswer.HintPrefix, StringComparison.Ordinal) ? "" : ans.Notes);
            }
        }

        /// <summary>
        /// Items not filled in yet. Informational only: nothing here blocks submitting the ticket.
        /// Empty names are filled by FillDefaults; unanswered checks are sent as "Not checked".
        /// </summary>
        /// <summary>Fills an empty client or technician name so the ticket is never blocked on them.</summary>
        public void FillDefaults(AuditAnalysis a)
        {
            if (string.IsNullOrWhiteSpace(Tenant))
                Tenant = !string.IsNullOrEmpty(a.DefaultTenant) ? a.DefaultTenant : (!string.IsNullOrEmpty(a.DomainName) ? a.DomainName : a.ServerName);
            if (string.IsNullOrWhiteSpace(Technician)) Technician = Environment.UserName;
        }

        public List<string> Validate(AuditAnalysis a)
        {
            var problems = new List<string>();
            if (string.IsNullOrWhiteSpace(Tenant)) problems.Add("Client name is empty (the server's organization, domain or name will be used).");
            if (string.IsNullOrWhiteSpace(Technician)) problems.Add("Technician is empty (your Windows user name will be used).");
            foreach (var item in ManualCatalog.For(a))
            {
                ManualAnswer ans = Answer(item.Id);
                if (item.Required && ans.Status == ManualCatalog.NotChecked)
                    problems.Add("Not checked: " + item.Title);
            }
            return problems;
        }
    }
}
