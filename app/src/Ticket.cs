using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace PolarniteAudit
{
    /// <summary>Builds the ticket email (subject, HTML and text bodies) and the PDF file.</summary>
    internal static class TicketComposer
    {
        public static string Subject(AppSettings s, AuditAnalysis a, DraftState d)
        {
            string t = string.IsNullOrWhiteSpace(s.SubjectTemplate) ? "Monthly Server Audit - {tenant} - {server} - {month}" : s.SubjectTemplate;
            return t.Replace("{tenant}", d.Tenant.Trim()).Replace("{server}", a.ServerName).Replace("{month}", a.MonthLabel)
                    .Replace("{status}", ReportPdf.OverallLabel(ReportPdf.Overall(a, d)));
        }

        public static string PdfFileName(AuditAnalysis a, DraftState d)
        {
            string tenant = Regex.Replace(d.Tenant ?? "", @"[^A-Za-z0-9._-]+", "-").Trim('-');
            string server = Regex.Replace(a.ServerName, @"[^A-Za-z0-9._-]+", "-");
            return "Server-Audit_" + (tenant.Length > 0 ? tenant + "_" : "") + server + "_" + a.MonthKey + ".pdf";
        }

        /// <summary>Writes the PDF next to the collector output and returns its path.</summary>
        public static string WritePdf(AuditAnalysis a, DraftState d, AppSettings s, string reportPath)
        {
            string dir = Path.GetDirectoryName(reportPath);
            string path = Path.Combine(dir, PdfFileName(a, d));
            File.WriteAllBytes(path, ReportPdf.Render(a, d, s.CompanyName));
            return path;
        }

        private static string Hex(Rgb c)
        {
            return "#" + ((int)Math.Round(c.R * 255)).ToString("X2") + ((int)Math.Round(c.G * 255)).ToString("X2") + ((int)Math.Round(c.B * 255)).ToString("X2");
        }

        private static string Chip(string text, Severity s)
        {
            string[] tint = { "#FEE2E2", "#FEF3C7", "#DBEAFE", "#DCFCE7", "#F3F4F6" };
            string[] ink = { "#B91C1C", "#B45309", "#1D4ED8", "#15803D", "#4B5563" };
            return "<span style=\"display:inline-block;background:" + tint[(int)s] + ";color:" + ink[(int)s] +
                   ";border-radius:10px;padding:2px 9px;font-size:11px;font-weight:bold;letter-spacing:.4px;white-space:nowrap\">" + J.HtmlEncode(text.ToUpperInvariant()) + "</span>";
        }

        public static string Html(AppSettings s, AuditAnalysis a, DraftState d, string pdfName)
        {
            Severity overall = ReportPdf.Overall(a, d);
            var items = ManualCatalog.For(a);
            var sb = new StringBuilder();
            sb.Append("<div style=\"font-family:'Segoe UI',Arial,sans-serif;color:#111827;font-size:14px;line-height:1.45;max-width:720px\">");
            sb.Append("<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"background:#0F2741;border-radius:10px;border-bottom:4px solid #38BDF8\"><tr>");
            sb.Append("<td style=\"padding:22px 26px\"><div style=\"color:#93C5FD;font-size:11px;font-weight:bold;letter-spacing:1.6px\">")
              .Append(J.HtmlEncode((s.CompanyName + " · Monthly Server Audit").ToUpperInvariant())).Append("</div>");
            sb.Append("<div style=\"color:#FFFFFF;font-size:26px;font-weight:bold;margin-top:6px\">").Append(J.HtmlEncode(a.ServerName)).Append("</div>");
            sb.Append("<div style=\"color:#CBD5E1;font-size:15px;margin-top:2px\">").Append(J.HtmlEncode(d.Tenant + " · " + a.MonthLabel)).Append("</div></td>");
            sb.Append("<td align=\"right\" style=\"padding:22px 26px;vertical-align:middle\"><span style=\"display:inline-block;background:")
              .Append(Hex(ReportPdf.Strong(overall))).Append(";color:#FFFFFF;border-radius:16px;padding:7px 16px;font-size:12px;font-weight:bold;letter-spacing:.8px;white-space:nowrap\">")
              .Append(J.HtmlEncode(ReportPdf.OverallLabel(overall).ToUpperInvariant())).Append("</span></td></tr></table>");

            // KPI row
            int answered = items.Count(i => d.Answer(i.Id).Status != ManualCatalog.NotChecked);
            var kpis = new[]
            {
                new KeyValuePair<string, string>(a.Count(Severity.Critical).ToString(CultureInfo.InvariantCulture), "Critical"),
                new KeyValuePair<string, string>(a.Count(Severity.Warning).ToString(CultureInfo.InvariantCulture), "Warnings"),
                new KeyValuePair<string, string>(a.Count(Severity.Pass).ToString(CultureInfo.InvariantCulture), "Passed"),
                new KeyValuePair<string, string>(answered + "/" + items.Count, "Manual checks"),
            };
            string[] kpiColor = { "#DC2626", "#D97706", "#16A34A", "#2563EB" };
            sb.Append("<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"8\" style=\"margin:14px 0 6px -8px\"><tr>");
            for (int i = 0; i < kpis.Length; i++)
                sb.Append("<td width=\"25%\" style=\"background:#F9FAFB;border:1px solid #E5E7EB;border-left:4px solid ").Append(kpiColor[i])
                  .Append(";border-radius:8px;padding:10px 14px\"><div style=\"font-size:24px;font-weight:bold;color:").Append(kpiColor[i]).Append("\">")
                  .Append(kpis[i].Key).Append("</div><div style=\"font-size:11px;font-weight:bold;color:#374151;letter-spacing:.6px\">")
                  .Append(kpis[i].Value.ToUpperInvariant()).Append("</div></td>");
            sb.Append("</tr></table>");

            if (a.PreviousAuditTime.HasValue)
                sb.Append("<p style=\"margin:6px 0 2px;color:#374151\"><b>Since the last audit</b> (").Append(J.HtmlEncode(J.FormatDate(a.PreviousAuditTime))).Append("): critical ")
                  .Append(a.PreviousCritical).Append(" \u2192 ").Append(a.Count(Severity.Critical)).Append(", warnings ").Append(a.PreviousWarning).Append(" \u2192 ").Append(a.Count(Severity.Warning))
                  .Append(", ").Append(J.HtmlEncode(J.Plural(a.Resolved.Count, "issue", "issues"))).Append(" resolved, ").Append(a.Findings.Count(f => f.IsNew)).Append(" new.</p>");

            // Snapshot line
            sb.Append("<p style=\"margin:8px 0 4px;color:#374151\">");
            sb.Append(J.HtmlEncode(a.OsName));
            if (!string.IsNullOrEmpty(a.OsSupportText)) sb.Append(" — ").Append(J.HtmlEncode(a.OsSupportText));
            if (!string.IsNullOrEmpty(d.ServerPurpose)) sb.Append("<br>Role: ").Append(J.HtmlEncode(d.ServerPurpose));
            sb.Append("<br>Audited ").Append(J.HtmlEncode(J.FormatDateTime(a.AuditTime))).Append(" by ").Append(J.HtmlEncode(d.Technician)).Append("</p>");

            if (!string.IsNullOrWhiteSpace(d.Summary))
                sb.Append("<div style=\"background:#F9FAFB;border-left:4px solid #2563EB;border-radius:6px;padding:10px 14px;margin:12px 0\"><div style=\"font-size:11px;font-weight:bold;color:#6B7280;letter-spacing:.7px\">TECHNICIAN NOTES</div>")
                  .Append(J.HtmlEncode(d.Summary.Trim())).Append("</div>");

            // Summary only: every critical, then warnings up to 10 rows; the PDF has the rest.
            var all = a.Findings.Where(f => f.Severity == Severity.Critical || f.Severity == Severity.Warning).ToList();
            var priority = all.Where(f => f.Severity == Severity.Critical).Concat(all.Where(f => f.Severity == Severity.Warning).Take(Math.Max(0, 10 - a.Count(Severity.Critical)))).ToList();
            int more = all.Count - priority.Count;
            sb.Append("<h3 style=\"font-size:16px;margin:18px 0 6px\">Findings needing attention</h3>");
            if (priority.Count == 0) sb.Append("<p style=\"color:#15803D\">No critical issues or warnings from the automated checks.</p>");
            else
            {
                sb.Append("<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"border-collapse:collapse\">");
                foreach (Finding f in priority)
                {
                    string note = d.FindingNotes.ContainsKey(f.Key) ? d.FindingNotes[f.Key] : "";
                    sb.Append("<tr><td style=\"padding:8px 10px 8px 0;border-bottom:1px solid #E5E7EB;vertical-align:top;width:96px\">").Append(Chip(Sev.Label(f.Severity), f.Severity))
                      .Append("</td><td style=\"padding:8px 0;border-bottom:1px solid #E5E7EB\"><b>").Append(J.HtmlEncode(f.Title)).Append("</b>");
                    if (f.IsNew) sb.Append(" ").Append(Chip("New", Severity.Info));
                    if (f.Detail.Length > 0) sb.Append("<br><span style=\"color:#6B7280;font-size:13px\">").Append(J.HtmlEncode(f.Detail)).Append("</span>");
                    if (!string.IsNullOrWhiteSpace(note)) sb.Append("<br><i style=\"color:#2563EB;font-size:13px\">Technician: ").Append(J.HtmlEncode(note.Trim())).Append("</i>");
                    sb.Append("</td></tr>");
                }
                sb.Append("</table>");
                if (more > 0)
                    sb.Append("<p style=\"color:#6B7280;font-size:13px;margin:8px 0 0\">+ ").Append(J.HtmlEncode(J.Plural(more, "more warning", "more warnings"))).Append(" in the attached report.</p>");
            }

            sb.Append("<h3 style=\"font-size:16px;margin:18px 0 6px\">Manual verification</h3>");
            sb.Append("<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"border-collapse:collapse\">");
            foreach (ManualItemDef item in items)
            {
                ManualAnswer ans = d.Answer(item.Id);
                sb.Append("<tr><td style=\"padding:7px 10px 7px 0;border-bottom:1px solid #E5E7EB;vertical-align:top;width:110px\">").Append(Chip(ans.Status, ReportPdf.ManualSeverity(ans.Status)))
                  .Append("</td><td style=\"padding:7px 0;border-bottom:1px solid #E5E7EB\">").Append(J.HtmlEncode(item.Title));
                if (!string.IsNullOrWhiteSpace(ans.Notes)) sb.Append("<br><span style=\"color:#6B7280;font-size:13px\">").Append(J.HtmlEncode(ans.Notes.Trim())).Append("</span>");
                sb.Append("</td></tr>");
            }
            sb.Append("</table>");

            int passed = a.Count(Severity.Pass);
            sb.Append("<p style=\"margin-top:18px;color:#6B7280;font-size:12px\">").Append(passed).Append(" automated checks passed. ")
              .Append("The full report is attached: <b>").Append(J.HtmlEncode(pdfName)).Append("</b>.<br>Generated by Polarnite Server Audit Tool (collector ")
              .Append(J.HtmlEncode(a.CollectorVersion)).Append(") on ").Append(J.HtmlEncode(Environment.MachineName)).Append(".</p></div>");
            return sb.ToString();
        }

        public static string Text(AppSettings s, AuditAnalysis a, DraftState d, string pdfName)
        {
            var items = ManualCatalog.For(a);
            var sb = new StringBuilder();
            sb.AppendLine(s.CompanyName.ToUpperInvariant() + " MONTHLY SERVER AUDIT");
            sb.AppendLine(a.ServerName + " | " + d.Tenant + " | " + a.MonthLabel);
            sb.AppendLine("Overall: " + ReportPdf.OverallLabel(ReportPdf.Overall(a, d)) + " | Critical " + a.Count(Severity.Critical) + " | Warnings " + a.Count(Severity.Warning) + " | Passed " + a.Count(Severity.Pass));
            sb.AppendLine(a.OsName + (string.IsNullOrEmpty(a.OsSupportText) ? "" : " - " + a.OsSupportText));
            sb.AppendLine("Audited " + J.FormatDateTime(a.AuditTime) + " by " + d.Technician);
            if (a.PreviousAuditTime.HasValue)
                sb.AppendLine("Since the last audit (" + J.FormatDate(a.PreviousAuditTime) + "): critical " + a.PreviousCritical + " -> " + a.Count(Severity.Critical) +
                              ", warnings " + a.PreviousWarning + " -> " + a.Count(Severity.Warning) + ", " + a.Resolved.Count + " resolved, " + a.Findings.Count(f => f.IsNew) + " new");
            if (!string.IsNullOrWhiteSpace(d.Summary)) { sb.AppendLine(); sb.AppendLine("TECHNICIAN NOTES"); sb.AppendLine(d.Summary.Trim()); }
            sb.AppendLine();
            sb.AppendLine("FINDINGS NEEDING ATTENTION");
            var priority = a.Findings.Where(f => f.Severity == Severity.Critical || f.Severity == Severity.Warning).ToList();
            if (priority.Count == 0) sb.AppendLine("  None.");
            foreach (Finding f in priority)
            {
                sb.AppendLine("  [" + Sev.Label(f.Severity).ToUpperInvariant() + "] " + f.Title + (f.IsNew ? " (new)" : ""));
                if (f.Detail.Length > 0) sb.AppendLine("      " + f.Detail);
                string note;
                if (d.FindingNotes.TryGetValue(f.Key, out note) && !string.IsNullOrWhiteSpace(note)) sb.AppendLine("      Technician: " + note.Trim());
            }
            sb.AppendLine();
            sb.AppendLine("MANUAL VERIFICATION");
            foreach (ManualItemDef item in items)
            {
                ManualAnswer ans = d.Answer(item.Id);
                sb.AppendLine("  [" + ans.Status + "] " + item.Title + (string.IsNullOrWhiteSpace(ans.Notes) ? "" : " - " + ans.Notes.Trim()));
            }
            sb.AppendLine();
            sb.AppendLine("Full report attached: " + pdfName);
            return sb.ToString();
        }
    }

    /// <summary>The audit lifecycle shared by the GUI and the command-line modes.</summary>
    internal static class Workflow
    {
        /// <summary>Analyses a report against the last submitted audit, when one is available.</summary>
        public static AuditAnalysis Analyze(AuditReport report, AppSettings s)
        {
            AuditReport previous = null;
            try
            {
                DraftState last = DraftStore.LoadLastAnswers();
                if (last != null && !string.IsNullOrEmpty(last.ReportPath) && File.Exists(last.ReportPath) &&
                    !string.Equals(Path.GetFullPath(last.ReportPath), Path.GetFullPath(report.Path), StringComparison.OrdinalIgnoreCase))
                    previous = AuditReport.Load(last.ReportPath);
            }
            catch (Exception ex) { Log.Write("Previous audit unavailable for comparison: " + ex.Message); }
            return Analyzer.Run(report, s.ExpectedAgentList, previous);
        }

        /// <summary>Scheduled (SYSTEM) run: collect, analyse and save a draft. Nothing is sent.</summary>
        public static int RunScheduled()
        {
            try
            {
                AppPaths.EnsureRoot();
                AppSettings s = AppSettings.Load();
                Log.Write("Scheduled audit starting.");
                string report = CollectorRunner.Run(new CollectorOptions { DeepAudit = s.DeepAudit, OnlineUpdateScan = s.OnlineUpdateScan, ExternalExposureCheck = s.ExternalExposureCheck },
                    line => { }, System.Threading.CancellationToken.None);
                AuditAnalysis a = Analyze(AuditReport.Load(report), s);
                DraftState existing = DraftStore.Load();
                DraftState d;
                if (existing != null && !existing.IsSubmitted && existing.MonthKey == a.MonthKey)
                {
                    // Same month, not yet submitted: refresh the evidence, keep the technician's answers.
                    d = existing;
                    d.ReportPath = report;
                    d.Source = "Scheduled";
                }
                else d = DraftStore.NewDraft(report, a, s, "Scheduled");
                d.ApplyAuto(a);
                DraftStore.Save(d);
                CollectorRunner.PruneRuns(s.KeepRunsMonths, report);
                Log.Write("Scheduled audit saved as draft: " + report);
                return 0;
            }
            catch (Exception ex)
            {
                Log.Write("Scheduled audit failed: " + ex);
                return 1;
            }
        }

        /// <summary>Validates, builds the PDF, emails it and marks the draft submitted.</summary>
        public static string Submit(AppSettings s, AuditAnalysis a, DraftState d, string pickupDirectory)
        {
            var problems = d.Validate(a);
            if (string.IsNullOrEmpty(pickupDirectory)) problems.AddRange(s.ValidateMail());
            if (problems.Count > 0) throw new InvalidOperationException("The ticket is not ready:\n\n• " + string.Join("\n• ", problems.ToArray()));

            string submittedAt = DateTime.Now.ToString("o", CultureInfo.InvariantCulture);
            string previous = d.SubmittedAt;
            d.SubmittedAt = submittedAt; // shown on the PDF sign-off
            string pdf;
            try
            {
                pdf = TicketComposer.WritePdf(a, d, s, d.ReportPath);
                string name = Path.GetFileName(pdf);
                Mailer.Send(s, TicketComposer.Subject(s, a, d), TicketComposer.Html(s, a, d, name), TicketComposer.Text(s, a, d, name), pdf, pickupDirectory);
            }
            catch
            {
                d.SubmittedAt = previous;
                throw;
            }
            d.Status = "Submitted";
            d.SubmittedTo = string.IsNullOrEmpty(pickupDirectory) ? s.ToAddress : pickupDirectory;
            d.PdfPath = pdf;
            DraftStore.Save(d);
            DraftStore.RecordSubmission(d);
            s.LastTechnician = d.Technician;
            s.Save();
            Log.Write("Submitted " + a.ServerName + " " + a.MonthKey + " to " + d.SubmittedTo);
            return pdf;
        }
    }
}
