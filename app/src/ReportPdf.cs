using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace PolarniteAudit
{
    /// <summary>Lays out the audit as a branded, paginated PDF.</summary>
    internal sealed class ReportPdf
    {
        // Palette
        private static readonly Rgb Navy = new Rgb(0x0F2741), NavyRing = new Rgb(0x173459), NavyRing2 = new Rgb(0x1C3D66);
        private static readonly Rgb Sky = new Rgb(0x38BDF8), SkySoft = new Rgb(0x93C5FD), Slate = new Rgb(0xCBD5E1), SlateDim = new Rgb(0x94A3B8);
        private static readonly Rgb Ink = new Rgb(0x111827), Muted = new Rgb(0x6B7280), Faint = new Rgb(0x9CA3AF);
        private static readonly Rgb Border = new Rgb(0xE5E7EB), Soft = new Rgb(0xF9FAFB), HeaderBg = new Rgb(0xF3F4F6), White = new Rgb(0xFFFFFF);
        private static readonly Rgb Accent = new Rgb(0x2563EB), BarBlue = new Rgb(0x3B82F6);

        private const double M = 44, CW = PdfDoc.Width - 2 * M, Top = 70, Bottom = PdfDoc.Height - 58;

        private readonly PdfDoc pdf = new PdfDoc();
        private readonly AuditAnalysis a;
        private readonly DraftState d;
        private readonly string company;
        private double y;

        private ReportPdf(AuditAnalysis analysis, DraftState draft, string companyName)
        {
            a = analysis; d = draft; company = string.IsNullOrWhiteSpace(companyName) ? "Server Audit" : companyName.Trim();
        }

        public static byte[] Render(AuditAnalysis analysis, DraftState draft, string companyName)
        {
            var r = new ReportPdf(analysis, draft, companyName);
            r.Build();
            return r.pdf.Save();
        }

        internal static Rgb Strong(Severity s)
        {
            switch (s)
            {
                case Severity.Critical: return new Rgb(0xDC2626);
                case Severity.Warning: return new Rgb(0xD97706);
                case Severity.Info: return new Rgb(0x2563EB);
                case Severity.Pass: return new Rgb(0x16A34A);
                default: return new Rgb(0x9CA3AF);
            }
        }

        private static Rgb Tint(Severity s)
        {
            switch (s)
            {
                case Severity.Critical: return new Rgb(0xFEE2E2);
                case Severity.Warning: return new Rgb(0xFEF3C7);
                case Severity.Info: return new Rgb(0xDBEAFE);
                case Severity.Pass: return new Rgb(0xDCFCE7);
                default: return new Rgb(0xF3F4F6);
            }
        }

        private static Rgb TintText(Severity s)
        {
            switch (s)
            {
                case Severity.Critical: return new Rgb(0xB91C1C);
                case Severity.Warning: return new Rgb(0xB45309);
                case Severity.Info: return new Rgb(0x1D4ED8);
                case Severity.Pass: return new Rgb(0x15803D);
                default: return new Rgb(0x4B5563);
            }
        }

        internal static Severity ManualSeverity(string status)
        {
            if (status == ManualCatalog.Pass) return Severity.Pass;
            if (status == ManualCatalog.Issue) return Severity.Warning;
            if (status == ManualCatalog.NotApplicable) return Severity.Unknown;
            return Severity.Info;
        }

        internal static Severity Overall(AuditAnalysis a, DraftState d)
        {
            bool manualIssue = ManualCatalog.For(a).Any(i => d.Answer(i.Id).Status == ManualCatalog.Issue);
            if (a.Count(Severity.Critical) > 0) return Severity.Critical;
            if (a.Count(Severity.Warning) > 0 || manualIssue) return Severity.Warning;
            return Severity.Pass;
        }

        internal static string OverallLabel(Severity s)
        {
            return s == Severity.Critical ? "Action required" : s == Severity.Warning ? "Needs attention" : "Healthy";
        }

        // ------------------------------------------------------------ page flow

        private void NewPage()
        {
            pdf.NewPage();
            pdf.Text(M, 38, a.ServerName, PdfFont.Bold, 8, Ink);
            double w = PdfDoc.Measure(a.ServerName, PdfFont.Bold, 8);
            pdf.Text(M + w, 38, "  ·  Monthly Server Audit  ·  " + a.MonthLabel, PdfFont.Regular, 8, Muted);
            pdf.TextRight(PdfDoc.Width - M, 38, company, PdfFont.Bold, 8, Muted);
            pdf.Line(M, 46, PdfDoc.Width - M, 46, Border, 0.6);
            y = Top;
        }

        private void Ensure(double h)
        {
            if (y + h > Bottom) NewPage();
        }

        private void Footers()
        {
            int n = pdf.PageCount;
            for (int i = 0; i < n; i++)
            {
                pdf.SelectPage(i);
                double fy = PdfDoc.Height - 34;
                pdf.Line(M, fy - 12, PdfDoc.Width - M, fy - 12, Border, 0.6);
                pdf.Text(M, fy, company + "  ·  " + d.Tenant + "  ·  " + a.ServerName + "  ·  " + a.MonthLabel, PdfFont.Regular, 7.5, Faint);
                pdf.TextRight(PdfDoc.Width - M, fy, "Page " + (i + 1) + " of " + n, PdfFont.Regular, 7.5, Faint);
            }
        }

        // ------------------------------------------------------------ primitives

        private double Chip(double x, double top, string text, Severity s)
        {
            string label = text.ToUpperInvariant();
            double w = PdfDoc.Measure(label, PdfFont.Bold, 6.8, 0.35) + 12;
            pdf.FillRoundRect(x, top, w, 13, 6.5, Tint(s));
            pdf.Text(x + 6, top + 9.1, label, PdfFont.Bold, 6.8, TintText(s), 0.35);
            return w;
        }

        private static double ChipWidth(string text) { return PdfDoc.Measure(text.ToUpperInvariant(), PdfFont.Bold, 6.8, 0.35) + 12; }

        private double Paragraph(string text, PdfFont f, double size, double lineHeight, Rgb color, double x, double width)
        {
            foreach (string line in PdfDoc.Wrap(text, f, size, width))
            {
                Ensure(lineHeight);
                pdf.Text(x, y + size, line, f, size, color);
                y += lineHeight;
            }
            return y;
        }

        private void SectionHeading(string title, string intro)
        {
            Ensure(90);
            pdf.FillRoundRect(M, y + 1, 4, 17, 2, Accent);
            pdf.Text(M + 12, y + 14.5, title, PdfFont.Bold, 15, Ink);
            y += 30;
            if (!string.IsNullOrEmpty(intro))
            {
                Paragraph(intro, PdfFont.Regular, 9.2, 13, Muted, M, CW);
                y += 6;
            }
        }

        private void SubHeading(string text)
        {
            Ensure(48);
            pdf.Text(M, y + 10, text, PdfFont.Bold, 10.2, Ink);
            y += 18;
        }

        // ------------------------------------------------------------ build

        private void Build()
        {
            pdf.Title = "Server audit — " + a.ServerName + " — " + a.MonthLabel;
            pdf.Author = string.IsNullOrEmpty(d.Technician) ? company : d.Technician;
            pdf.Subject = d.Tenant;
            Cover();
            Findings();
            foreach (Section s in a.Sections) RenderSection(s);
            Manual();
            if (a.Coverage.Rows.Count > 0)
            {
                SectionHeading("Collection coverage", "These checks returned no data or partial data, usually because a feature is not installed, the provider timed out, or permissions were insufficient. They are not counted as passes.");
                Table(a.Coverage);
            }
            Footers();
        }

        private void Cover()
        {
            pdf.NewPage();
            const double band = 172;
            pdf.FillRect(0, 0, PdfDoc.Width, band, Navy);
            pdf.PushClip(0, 0, PdfDoc.Width, band);
            pdf.FillCircle(560, 10, 150, NavyRing);
            pdf.FillCircle(612, 150, 90, NavyRing2);
            pdf.PopClip();
            pdf.FillRect(0, band, PdfDoc.Width, 4, Sky);

            pdf.Text(M, 44, (company + "   ·   Monthly Server Audit").ToUpperInvariant(), PdfFont.Bold, 8.2, SkySoft, 1.4);
            double nameSize = 30;
            while (nameSize > 16 && PdfDoc.Measure(a.ServerName, PdfFont.Bold, nameSize) > CW - 170) nameSize -= 1;
            pdf.Text(M, 92, a.ServerName, PdfFont.Bold, nameSize, White);
            string subtitle = (string.IsNullOrEmpty(d.Tenant) ? "" : d.Tenant + "   ·   ") + a.MonthLabel;
            pdf.Text(M, 118, subtitle, PdfFont.Regular, 12, Slate);
            string meta = "Audited " + J.FormatDateTime(a.AuditTime) + (string.IsNullOrEmpty(d.Technician) ? "" : "   ·   " + d.Technician);
            if (!string.IsNullOrEmpty(d.ServerPurpose)) meta += "   ·   " + d.ServerPurpose;
            pdf.Text(M, 142, J.Shorten(meta, 110), PdfFont.Regular, 8.6, SlateDim);

            Severity overall = Overall(a, d);
            string pill = OverallLabel(overall).ToUpperInvariant();
            double pw = PdfDoc.Measure(pill, PdfFont.Bold, 9.5, 0.9) + 30;
            double px = PdfDoc.Width - M - pw;
            pdf.TextRight(PdfDoc.Width - M, 70, "OVERALL STATUS", PdfFont.Bold, 6.8, SkySoft);
            pdf.FillRoundRect(px, 78, pw, 26, 13, Strong(overall));
            pdf.FillCircle(px + 13, 91, 3.2, White);
            pdf.Text(px + 21, 94.4, pill, PdfFont.Bold, 9.5, White, 0.9);

            // KPI cards
            y = 200;
            var items = ManualCatalog.For(a);
            int answered = items.Count(i => d.Answer(i.Id).Status != ManualCatalog.NotChecked);
            int issues = items.Count(i => d.Answer(i.Id).Status == ManualCatalog.Issue);
            var cards = new[]
            {
                new { Value = a.Count(Severity.Critical).ToString(CultureInfo.InvariantCulture), Label = "Critical", Sub = "need a ticket" + (a.PreviousCritical >= 0 ? " · was " + a.PreviousCritical : ""), Sev = Severity.Critical },
                new { Value = a.Count(Severity.Warning).ToString(CultureInfo.InvariantCulture), Label = "Warnings", Sub = "noted, no ticket" + (a.PreviousWarning >= 0 ? " · was " + a.PreviousWarning : ""), Sev = Severity.Warning },
                new { Value = a.Count(Severity.Pass).ToString(CultureInfo.InvariantCulture), Label = "Passed", Sub = "checks healthy", Sev = Severity.Pass },
                new { Value = answered + "/" + items.Count, Label = "Manual checks", Sub = issues > 0 ? J.Plural(issues, "issue", "issues") + " noted" : "verified by technician", Sev = Severity.Info },
            };
            const double gap = 12, ch = 76;
            double cw = (CW - 3 * gap) / 4;
            for (int i = 0; i < cards.Length; i++)
            {
                double x = M + i * (cw + gap);
                pdf.FillRoundRect(x, y, cw, ch, 8, Soft);
                pdf.StrokeRoundRect(x, y, cw, ch, 8, Border, 0.7);
                pdf.FillRoundRect(x + 10, y + 14, 3.5, ch - 28, 1.75, Strong(cards[i].Sev));
                pdf.Text(x + 22, y + 40, cards[i].Value, PdfFont.Bold, 26, Strong(cards[i].Sev));
                pdf.Text(x + 22, y + 55, cards[i].Label.ToUpperInvariant(), PdfFont.Bold, 7.4, Ink, 0.6);
                pdf.Text(x + 22, y + 66, cards[i].Sub, PdfFont.Regular, 7.6, Muted);
            }
            y += ch + 26;

            // Executive summary
            pdf.Text(M, y + 10, "Executive summary", PdfFont.Bold, 12.5, Ink);
            y += 22;
            string summary = ExecutiveSummary(items, answered, issues);
            var lines = PdfDoc.Wrap(summary, PdfFont.Regular, 9.8, CW - 32);
            var noteLines = string.IsNullOrWhiteSpace(d.Summary) ? new List<string>() : PdfDoc.Wrap(d.Summary.Trim(), PdfFont.Regular, 9.6, CW - 32);
            double boxH = 14 + lines.Count * 14 + (noteLines.Count > 0 ? 24 + noteLines.Count * 13.5 : 0) + 6;
            pdf.FillRoundRect(M, y, CW, boxH, 8, Soft);
            pdf.FillRoundRect(M, y, 4, boxH, 2, Strong(overall));
            double ty = y + 12;
            foreach (string l in lines) { pdf.Text(M + 18, ty + 8, l, PdfFont.Regular, 9.8, Ink); ty += 14; }
            if (noteLines.Count > 0)
            {
                ty += 8;
                pdf.Text(M + 18, ty + 6, "TECHNICIAN NOTES", PdfFont.Bold, 7, Muted, 0.7);
                ty += 16;
                foreach (string l in noteLines) { pdf.Text(M + 18, ty + 8, l, PdfFont.Regular, 9.6, Ink); ty += 13.5; }
            }
            y += boxH + 22;

            // Needs a ticket: every critical finding and every manual check marked "Issue found".
            var ticket = a.Findings.Where(f => f.Severity == Severity.Critical).ToList();
            var manualIssues = items.Where(i => d.Answer(i.Id).Status == ManualCatalog.Issue && !d.Answer(i.Id).AutoSet).ToList(); // auto-filled issues already appear as findings
            Ensure(60);
            pdf.Text(M, y + 10, "Needs a ticket", PdfFont.Bold, 12.5, Ink);
            y += 24;
            if (ticket.Count == 0 && manualIssues.Count == 0)
                Paragraph("Nothing needs a fix ticket this month.", PdfFont.Regular, 9.6, 13, Ink, M, CW);
            int n = 0;
            foreach (Finding f in ticket.Take(10)) PriorityRow(++n, f.Severity, f.Title, f.Detail);
            foreach (var i in manualIssues) PriorityRow(++n, Severity.Critical, i.Title, d.Answer(i.Id).Notes);
            if (ticket.Count > 10) { y += 2; Paragraph("+ " + J.Plural(ticket.Count - 10, "more critical item", "more critical items") + " in Findings.", PdfFont.Italic, 8.8, 12, Muted, M + 26, CW - 26); }
            int warnings = a.Count(Severity.Warning), practice = a.Count(Severity.Info);
            if (warnings + practice > 0)
            {
                y += 4;
                Paragraph(J.Plural(warnings, "warning", "warnings") + " and " + J.Plural(practice, "best-practice recommendation", "best-practice recommendations") +
                    " are listed under Findings. They are noted for the record and do not need a ticket.", PdfFont.Italic, 8.8, 12, Muted, M, CW);
            }
            y += 12;

            // Snapshot
            Ensure(80);
            pdf.Text(M, y + 10, "Server snapshot", PdfFont.Bold, 12.5, Ink);
            y += 24;
            KeyValues(a.Snapshot);
        }

        private string ExecutiveSummary(List<ManualItemDef> items, int answered, int issues)
        {
            int crit = a.Count(Severity.Critical), warn = a.Count(Severity.Warning), pass = a.Count(Severity.Pass);
            string s = a.ServerName + (string.IsNullOrEmpty(a.OsName) ? "" : " (" + a.OsName + ")") + " was audited on " + J.FormatDate(a.AuditTime) + ". ";
            s += "The automated checks found " + J.Plural(crit, "critical issue", "critical issues") + " that need a ticket, " + J.Plural(warn, "warning", "warnings") + " to note and " +
                 J.Plural(a.Count(Severity.Info), "best-practice recommendation", "best-practice recommendations") + ", with " + pass + " checks passing. ";
            var critical = a.Findings.Where(f => f.Severity == Severity.Critical).Select(f => f.Title).Take(3).ToList();
            if (crit > 0) s += "Most urgent: " + string.Join("; ", critical.ToArray()) + ". ";
            else if (warn > 0) s += "Nothing needs a ticket; the warnings are noted for normal maintenance. ";
            else s += "No issues requiring action were found. ";
            if (a.PreviousAuditTime.HasValue)
                s += "Since the last audit (" + J.FormatDate(a.PreviousAuditTime) + "), " + J.Plural(a.Resolved.Count, "issue was", "issues were") + " resolved and " +
                     J.Plural(a.Findings.Count(f => f.IsNew), "new issue appeared", "new issues appeared") + ". ";
            int auto = items.Count(i => d.Answer(i.Id).AutoSet);
            if (items.Count > 0)
            {
                s += answered + " of " + items.Count + " manual checks are complete" + (auto > 0 ? " (" + auto + " verified automatically from server evidence)" : "");
                s += issues > 0 ? ", with " + J.Plural(issues, "issue", "issues") + " noted." : (answered == items.Count ? ", with no issues." : ".");
            }
            return s;
        }

        private void PriorityRow(int n, Severity s, string title, string detail)
        {
            var titleLines = PdfDoc.Wrap(title, PdfFont.Bold, 9.8, CW - 104);
            var detailLines = string.IsNullOrEmpty(detail) ? new List<string>() : PdfDoc.Wrap(J.Shorten(detail, 260), PdfFont.Regular, 8.6, CW - 104);
            double h = Math.Max(20, titleLines.Count * 13 + detailLines.Count * 11.5) + 10;
            Ensure(h);
            pdf.FillCircle(M + 9, y + 8, 9, Tint(s));
            string num = n.ToString(CultureInfo.InvariantCulture);
            pdf.Text(M + 9 - PdfDoc.Measure(num, PdfFont.Bold, 8.5) / 2, y + 11, num, PdfFont.Bold, 8.5, TintText(s));
            Chip(M + 26, y + 1.5, Sev.Label(s), s);
            double ty = y;
            foreach (string l in titleLines) { pdf.Text(M + 104, ty + 10, l, PdfFont.Bold, 9.8, Ink); ty += 13; }
            foreach (string l in detailLines) { pdf.Text(M + 104, ty + 9, l, PdfFont.Regular, 8.6, Muted); ty += 11.5; }
            y += h;
            pdf.Line(M + 104, y - 5, PdfDoc.Width - M, y - 5, Border, 0.5);
        }

        // ------------------------------------------------------------ findings

        private void Findings()
        {
            NewPage();
            var issues = a.Findings.Where(f => f.Severity != Severity.Pass).ToList();
            SectionHeading("Findings", issues.Count == 0
                ? "No issues were found by the automated checks."
                : J.Plural(issues.Count, "item", "items") + " from the automated checks, most severe first. Technician notes are shown in blue.");
            Severity? group = null;
            foreach (Finding f in issues)
            {
                if (group != f.Severity)
                {
                    group = f.Severity;
                    y += 4;
                    SubHeading(f.Severity == Severity.Critical ? "Critical: open a ticket" : f.Severity == Severity.Warning ? "Warnings: noted, no ticket" : f.Severity == Severity.Info ? "Best practice: recommendations" : "Not checked");
                }
                FindingCard(f);
            }

            var passed = a.Findings.Where(f => f.Severity == Severity.Pass).ToList();
            if (passed.Count > 0)
            {
                y += 8;
                SubHeading("Passed checks");
                double colW = (CW - 16) / 2;
                for (int i = 0; i < passed.Count; i += 2)
                {
                    var left = PdfDoc.Wrap(passed[i].Title, PdfFont.Regular, 8.8, colW - 16);
                    var right = i + 1 < passed.Count ? PdfDoc.Wrap(passed[i + 1].Title, PdfFont.Regular, 8.8, colW - 16) : new List<string>();
                    double h = Math.Max(left.Count, right.Count) * 11.5 + 6;
                    Ensure(h);
                    PassItem(M, left);
                    if (right.Count > 0) PassItem(M + colW + 16, right);
                    y += h;
                }
            }
        }

        private void PassItem(double x, List<string> lines)
        {
            pdf.FillCircle(x + 4, y + 5.5, 3.6, Strong(Severity.Pass));
            pdf.Line(x + 2.4, y + 5.6, x + 3.6, y + 6.9, White, 0.9);
            pdf.Line(x + 3.6, y + 6.9, x + 5.8, y + 4.3, White, 0.9);
            double ty = y;
            foreach (string l in lines) { pdf.Text(x + 14, ty + 8.6, l, PdfFont.Regular, 8.8, Ink); ty += 11.5; }
        }

        private void FindingCard(Finding f)
        {
            // Compact two-column card: severity chip and area on the left, text on the right.
            const double textX = M + 112;
            double inner = PdfDoc.Width - M - 14 - textX;
            var title = PdfDoc.Wrap(f.Title, PdfFont.Bold, 10.2, inner);
            var detail = PdfDoc.Wrap(f.Detail, PdfFont.Regular, 8.8, inner);
            string noteText = d.FindingNotes.ContainsKey(f.Key) ? d.FindingNotes[f.Key] : "";
            var note = string.IsNullOrWhiteSpace(noteText) ? new List<string>() : PdfDoc.Wrap("Technician: " + noteText.Trim(), PdfFont.Italic, 8.7, inner);
            double body = title.Count * 13.2 + (detail.Count > 0 ? 2 + detail.Count * 11.6 : 0) + (note.Count > 0 ? 5 + note.Count * 11.6 : 0);
            double h = Math.Max(f.IsNew ? 42 : 36, body) + 20;
            Ensure(h + 7);
            pdf.StrokeRoundRect(M, y, CW, h, 7, Border, 0.8);
            pdf.FillRoundRect(M + 8, y + 9, 3.5, h - 18, 1.75, Strong(f.Severity));
            Chip(M + 22, y + 10, Sev.Label(f.Severity), f.Severity);
            pdf.Text(M + 23, y + 35, f.Area.ToUpperInvariant(), PdfFont.Bold, 6.8, Faint, 0.6);
            if (f.IsNew) Chip(M + 22, y + 42, "New", Severity.Info);
            double ty = y + 10;
            foreach (string l in title) { pdf.Text(textX, ty + 9.6, l, PdfFont.Bold, 10.2, Ink); ty += 13.2; }
            if (detail.Count > 0) { ty += 2; foreach (string l in detail) { pdf.Text(textX, ty + 8.8, l, PdfFont.Regular, 8.8, Muted); ty += 11.6; } }
            if (note.Count > 0) { ty += 5; foreach (string l in note) { pdf.Text(textX, ty + 8.8, l, PdfFont.Italic, 8.7, Accent); ty += 11.6; } }
            y += h + 7;
        }

        // ------------------------------------------------------------ sections

        private void RenderSection(Section s)
        {
            y += 10;
            SectionHeading(s.Title, s.Intro);
            foreach (Block b in s.Blocks)
            {
                if (b is KeyValueBlock) KeyValues((KeyValueBlock)b);
                else if (b is TableBlock) Table((TableBlock)b);
                else if (b is BarBlock) Bars((BarBlock)b);
                else if (b is NoteBlock) { Paragraph(((NoteBlock)b).Text, PdfFont.Italic, 8.4, 11.5, Muted, M, CW); y += 8; }
            }
        }

        private void KeyValues(KeyValueBlock kv)
        {
            if (kv.Items.Count == 0) return;
            double colW = (CW - 24) / 2;
            for (int i = 0; i < kv.Items.Count; i += 2)
            {
                var left = PdfDoc.Wrap(kv.Items[i].Value, PdfFont.Regular, 9.6, colW);
                var right = i + 1 < kv.Items.Count ? PdfDoc.Wrap(kv.Items[i + 1].Value, PdfFont.Regular, 9.6, colW) : new List<string>();
                double h = 13 + Math.Max(left.Count, right.Count) * 13 + 11;
                Ensure(h);
                KvCell(M, kv.Items[i].Key, left, h);
                if (i + 1 < kv.Items.Count) KvCell(M + colW + 24, kv.Items[i + 1].Key, right, h);
                y += h;
            }
            y += 6;
        }

        private void KvCell(double x, string key, List<string> lines, double rowHeight)
        {
            pdf.Text(x, y + 7, key.ToUpperInvariant(), PdfFont.Bold, 6.9, Muted, 0.6);
            double ty = y + 13;
            foreach (string l in lines) { pdf.Text(x, ty + 9.6, l, PdfFont.Regular, 9.6, Ink); ty += 13; }
            pdf.Line(x, y + rowHeight - 6, x + (CW - 24) / 2, y + rowHeight - 6, Border, 0.5);
        }

        private void Table(TableBlock t)
        {
            if (!string.IsNullOrEmpty(t.Caption)) SubHeading(t.Caption);
            if (t.Rows.Count == 0)
            {
                Paragraph(t.EmptyText, PdfFont.Italic, 8.8, 12, Muted, M, CW);
                y += 10;
                return;
            }
            double total = t.Widths.Sum();
            double[] w = t.Widths.Select(v => v / total * CW).ToArray();
            const double pad = 7, fs = 8.6, lh = 11.2;
            Action header = () =>
            {
                pdf.FillRoundRect(M, y, CW, 19, 4, HeaderBg);
                double hx = M;
                for (int c = 0; c < t.Columns.Length; c++) { pdf.Text(hx + pad, y + 12.6, t.Columns[c].ToUpperInvariant(), PdfFont.Bold, 6.8, Muted, 0.5); hx += w[c]; }
                y += 19;
            };
            Ensure(19 + 24);
            header();
            for (int r = 0; r < t.Rows.Count; r++)
            {
                Cell[] row = t.Rows[r];
                var wrapped = new List<List<string>>();
                double rowH = 0;
                for (int c = 0; c < t.Columns.Length; c++)
                {
                    Cell cell = c < row.Length ? row[c] : new Cell("");
                    if (cell.Chip.HasValue) { wrapped.Add(null); rowH = Math.Max(rowH, 13); continue; }
                    var lines = PdfDoc.Wrap(cell.Text, c == 0 ? PdfFont.Bold : PdfFont.Regular, fs, w[c] - 2 * pad);
                    wrapped.Add(lines);
                    rowH = Math.Max(rowH, lines.Count * lh);
                }
                rowH += 11;
                if (y + rowH > Bottom) { NewPage(); header(); }
                if (r % 2 == 1) pdf.FillRect(M, y, CW, rowH, Soft);
                double cx = M;
                for (int c = 0; c < t.Columns.Length; c++)
                {
                    Cell cell = c < row.Length ? row[c] : new Cell("");
                    if (cell.Chip.HasValue)
                    {
                        string text = cell.Text.Length > 0 ? cell.Text : Sev.Label(cell.Chip.Value);
                        if (ChipWidth(text) > w[c] - pad)
                        {
                            while (ChipWidth(text + "…") > w[c] - pad && text.Length > 3) text = text.Substring(0, text.Length - 1);
                            text += "…";
                        }
                        Chip(cx + pad, y + 5.5, text, cell.Chip.Value);
                    }
                    else
                    {
                        double ty = y + 5.5;
                        foreach (string l in wrapped[c]) { pdf.Text(cx + pad, ty + 8.4, l, c == 0 ? PdfFont.Bold : PdfFont.Regular, fs, c == 0 ? Ink : new Rgb(0x374151)); ty += lh; }
                    }
                    cx += w[c];
                }
                y += rowH;
                pdf.Line(M, y, M + CW, y, Border, 0.5);
            }
            y += 16;
        }

        private void Bars(BarBlock b)
        {
            foreach (BarItem item in b.Items)
            {
                Ensure(36);
                pdf.Text(M, y + 10, item.Label, PdfFont.Bold, 9.6, Ink);
                string pct = Math.Round(item.UsedFraction * 100).ToString(CultureInfo.InvariantCulture) + "% used";
                pdf.TextRight(PdfDoc.Width - M, y + 10, item.Right + "   ·   " + pct, PdfFont.Regular, 8.8, Muted);
                pdf.FillRoundRect(M, y + 16, CW, 8, 4, Border);
                double fill = Math.Max(8, CW * item.UsedFraction);
                pdf.FillRoundRect(M, y + 16, fill, 8, 4, item.Severity == Severity.Pass ? BarBlue : Strong(item.Severity));
                y += 36;
            }
            if (b.Items.Count > 0) y += 8;
        }

        // ------------------------------------------------------------ manual checks

        private void Manual()
        {
            y += 10;
            SectionHeading("Manual verification", "Items the technician confirmed in consoles and systems the collector cannot reach (backup, RMM, EDR, firewall).");
            var t = new TableBlock(null, new[] { "Status", "Check", "Notes" }, new[] { 1.25, 3.4, 3.6 });
            foreach (ManualItemDef item in ManualCatalog.For(a))
            {
                ManualAnswer ans = d.Answer(item.Id);
                t.Add(new Cell(ans.Status, ManualSeverity(ans.Status)), item.Title, ans.Notes);
            }
            Table(t);
            Ensure(56);
            pdf.FillRoundRect(M, y, CW, 44, 8, Soft);
            pdf.Text(M + 16, y + 18, "COMPLETED BY", PdfFont.Bold, 6.8, Muted, 0.6);
            pdf.Text(M + 16, y + 33, string.IsNullOrEmpty(d.Technician) ? "—" : d.Technician, PdfFont.Bold, 10.5, Ink);
            pdf.Text(M + CW / 2, y + 18, "SUBMITTED", PdfFont.Bold, 6.8, Muted, 0.6);
            DateTime submitted;
            string when = DateTime.TryParse(d.SubmittedAt, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out submitted)
                ? J.FormatDateTime(submitted.ToLocalTime()) : J.FormatDateTime(DateTime.Now);
            pdf.Text(M + CW / 2, y + 33, when, PdfFont.Regular, 10.5, Ink);
            y += 60;
        }
    }
}
