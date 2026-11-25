using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Forms;

[assembly: System.Reflection.AssemblyTitle("Polarnite Server Audit Tool")]
[assembly: System.Reflection.AssemblyProduct("Polarnite Server Audit Tool")]
[assembly: System.Reflection.AssemblyCompany("Polarnite")]
[assembly: System.Reflection.AssemblyVersion("1.0.0.0")]
[assembly: System.Reflection.AssemblyFileVersion("1.0.0.0")]

namespace PolarniteAudit
{
    internal static class AppInfo
    {
        public const string Name = "Polarnite Server Audit Tool";
        public const string ExeName = "PolarniteServerAuditTool.exe";
    }

    internal static class Program
    {
        /// <summary>
        ///   (no args)                          GUI
        ///   --scheduled                        collect and save a draft (used by the monthly task)
        ///   --render &lt;report.json&gt; &lt;dir&gt;      test: write PDF, email bodies and an .eml for a sample-completed draft
        ///   --screenshot &lt;report.json&gt; &lt;dir&gt;  test: save PNGs of the main window tabs
        ///   --update                           download the newest build from GitHub and replace this exe (for RMM scripts; exit 0 updated, 2 already current, 1 failed)
        ///   --after-update                     GUI started by the updater: waits for the old version to close
        /// </summary>
        [STAThread]
        private static int Main(string[] args)
        {
            string mode = args.Length > 0 ? args[0].ToLowerInvariant() : "";
            try
            {
                if (mode == "--scheduled") return Workflow.RunScheduled();
                if (mode == "--update") return Updater.UpdateFromCommandLine();
                if (mode == "--render" && args.Length >= 3) return Render(args[1], args[2], args.Length >= 4 ? args[3] : null);
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                if (mode == "--screenshot" && args.Length >= 3) return Screenshot(args[1], args[2], args.Length >= 4 ? args[3] : null);

                AppPaths.MigrateLegacy();
                bool afterUpdate = mode == "--after-update";
                bool first;
                using (var mutex = new Mutex(true, @"Global\PolarniteServerAudit", out first))
                {
                    if (!first && afterUpdate)
                    {
                        try { first = mutex.WaitOne(TimeSpan.FromSeconds(30)); }
                        catch (AbandonedMutexException) { first = true; }
                    }
                    if (!first)
                    {
                        MessageBox.Show(AppInfo.Name + " is already open on this computer.", AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
                        return 0;
                    }
                    Application.ThreadException += (s, e) =>
                    {
                        Log.Write("UI error: " + e.Exception);
                        MessageBox.Show(e.Exception.Message, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    };
                    if (afterUpdate) { Updater.CleanupOld(); Log.Write("Started after an update; build " + Updater.CurrentBuiltText + "."); }
                    Updater.RefreshScheduledCopy();
                    Application.Run(new MainForm());
                }
                return 0;
            }
            catch (Exception ex)
            {
                Log.Write("Fatal (" + mode + "): " + ex);
                if (mode == "") MessageBox.Show(ex.ToString(), AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return 1;
            }
        }

        /// <summary>Fills a draft the way a technician would, for test output.</summary>
        private static DraftState SampleDraft(string reportPath, AuditAnalysis a, AppSettings s)
        {
            DraftState d = DraftStore.NewDraft(reportPath, a, s, "Manual");
            d.ApplyAuto(a);
            d.Tenant = string.IsNullOrEmpty(d.Tenant) ? "Contoso Dental" : d.Tenant;
            d.Technician = "Sample Technician";
            d.ServerPurpose = "Domain controller and file server";
            d.Summary = "Patched and restarted during the maintenance window. Veeam job reviewed; offsite copy current. Disk cleanup scheduled for D: next week.";
            foreach (ManualItemDef item in ManualCatalog.For(a))
            {
                ManualAnswer ans = d.Answer(item.Id);
                if (ans.AutoSet) continue; // keep the evidence-based answers
                ans.Status = item.Required ? ManualCatalog.Pass : ManualCatalog.NotApplicable;
            }
            d.Answer("rmm_health").Notes = "Online, no alerts.";
            Finding first = a.Findings.FirstOrDefault(f => f.Severity == Severity.Critical || f.Severity == Severity.Warning);
            if (first != null) d.FindingNotes[first.Key] = "Scheduled for the next maintenance window (approved by client).";
            return d;
        }

        private static int Render(string reportPath, string outDir, string previousPath)
        {
            Directory.CreateDirectory(outDir);
            AppSettings s = AppSettings.Load();
            if (!AppSettings.IsEmail(s.FromAddress)) s.FromAddress = "server-audit@example.com";
            AuditReport report = AuditReport.Load(reportPath);
            AuditAnalysis a = Analyzer.Run(report, s.ExpectedAgentList, string.IsNullOrEmpty(previousPath) ? null : AuditReport.Load(previousPath));
            DraftState d = SampleDraft(reportPath, a, s);

            var sb = new StringBuilder();
            sb.AppendLine("Server: " + a.ServerName + " | Month: " + a.MonthLabel + " | Tenant: " + d.Tenant);
            sb.AppendLine("Counts: critical " + a.Count(Severity.Critical) + ", warning " + a.Count(Severity.Warning) + ", info " + a.Count(Severity.Info) + ", pass " + a.Count(Severity.Pass));
            sb.AppendLine("Subject: " + TicketComposer.Subject(s, a, d));
            sb.AppendLine();
            foreach (Finding f in a.Findings) sb.AppendLine("[" + Sev.Label(f.Severity) + "] " + f.Area + " | " + f.Title + " | " + f.Detail);
            sb.AppendLine();
            sb.AppendLine("Auto-verified manual checks:");
            foreach (var kv in a.AutoAnswers) sb.AppendLine("  " + kv.Key + " = " + kv.Value.Status + " | " + kv.Value.Notes);
            foreach (var kv in a.AutoHints) sb.AppendLine("  hint " + kv.Key + " | " + kv.Value);
            if (a.PreviousAuditTime.HasValue) sb.AppendLine("Compared with " + J.FormatDate(a.PreviousAuditTime) + ": critical " + a.PreviousCritical + " -> " + a.Count(Severity.Critical) + ", warnings " + a.PreviousWarning + " -> " + a.Count(Severity.Warning) + ", new " + a.Findings.Count(f => f.IsNew) + ", resolved " + a.Resolved.Count);
            sb.AppendLine();
            sb.AppendLine("Coverage gaps: " + a.Coverage.Rows.Count);
            foreach (Cell[] row in a.Coverage.Rows) sb.AppendLine("  " + row[0].Text + " " + row[1].Text + " " + row[2].Text);
            sb.AppendLine();
            sb.AppendLine("Validation before answers: " + string.Join(" / ", DraftStore.NewDraft(reportPath, a, s, "Manual").Validate(a).ToArray()));
            sb.AppendLine("Validation after answers: " + string.Join(" / ", d.Validate(a).ToArray()));

            string name = TicketComposer.PdfFileName(a, d);
            File.WriteAllText(Path.Combine(outDir, "email.html"), TicketComposer.Html(s, a, d, name), Encoding.UTF8);
            File.WriteAllText(Path.Combine(outDir, "email.txt"), TicketComposer.Text(s, a, d, name), Encoding.UTF8);

            // Full submit path, delivering to a pickup folder instead of SMTP.
            string reportCopy = Path.Combine(outDir, Path.GetFileName(reportPath));
            if (!string.Equals(Path.GetFullPath(reportPath), Path.GetFullPath(reportCopy), StringComparison.OrdinalIgnoreCase)) File.Copy(reportPath, reportCopy, true);
            d.ReportPath = reportCopy;
            string pdf = Workflow.Submit(s, a, d, Path.Combine(outDir, "mail"));
            sb.AppendLine("PDF: " + pdf);
            sb.AppendLine("Draft status after submit: " + d.Status + " to " + d.SubmittedTo);
            File.WriteAllText(Path.Combine(outDir, "render-result.txt"), sb.ToString(), Encoding.UTF8);
            return 0;
        }

        private static int Screenshot(string reportPath, string outDir, string size)
        {
            using (var form = new MainForm(false))
            {
                form.StartPosition = FormStartPosition.Manual;
                form.Location = new System.Drawing.Point(-4000, -4000);
                form.ShowInTaskbar = false;
                form.Show();
                AppSettings s = AppSettings.Load();
                AuditAnalysis a = Analyzer.Run(AuditReport.Load(reportPath), s.ExpectedAgentList);
                DraftState d = DraftStore.NewDraft(reportPath, a, s, "Scheduled");
                d.ApplyAuto(a);
                d.Tenant = "Contoso Dental";
                d.Technician = "Sample Technician";
                d.Answer("backup_last_success").Status = ManualCatalog.Pass;
                d.Answer("backup_last_success").Notes = "Veeam nightly job OK 24 Nov 23:14";
                d.Answer("backup_failures").Status = ManualCatalog.Issue;
                form.LoadForPreview(reportPath, d);
                Application.DoEvents();
                System.Text.RegularExpressions.Match m = System.Text.RegularExpressions.Regex.Match(size ?? "", @"^(\d+)x(\d+)$");
                if (m.Success) form.ResizeForTest(new System.Drawing.Size(int.Parse(m.Groups[1].Value), int.Parse(m.Groups[2].Value)));
                form.SaveScreenshots(outDir);
                form.Close();
            }
            return 0;
        }
    }
}
