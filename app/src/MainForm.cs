using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace PolarniteAudit
{
    internal sealed class MainForm : Form
    {
        internal static readonly Color Navy = Color.FromArgb(15, 39, 65), SkySoft = Color.FromArgb(147, 197, 253), SlateText = Color.FromArgb(203, 213, 225);
        internal static readonly Color Accent = Color.FromArgb(37, 99, 235), Soft = Color.FromArgb(243, 244, 246), Border = Color.FromArgb(229, 231, 235), MutedText = Color.FromArgb(107, 114, 128);

        private readonly bool persist;
        private AppSettings settings;
        private AuditReport report;
        private AuditAnalysis analysis;
        private DraftState draft;
        private DraftState lastAnswers;
        private CancellationTokenSource cts;
        private bool loading, busy;
        private int checksDone;
        private readonly System.Windows.Forms.Timer saveTimer = new System.Windows.Forms.Timer { Interval = 800 };

        private Label lblServer, lblSub, lblPill, lblBanner, lblProgress, lblReady, lblSubject, lblCounts, lblOverrides;
        private Button btnResetOverrides;
        private Button btnRun, btnCancel, btnOpen, btnSettings, btnUpdate, btnNinja, btnPreview, btnSubmit;
        private CancellationTokenSource ninjaCts;
        private CheckBox chkDeep, chkOnline, chkShowPassed;
        private TabControl tabs;
        private TabPage tabOverview, tabFindings, tabManual, tabLog;
        private TextBox txtTenant, txtTech, txtPurpose, txtSummary, txtLog;
        private ListView lvSnapshot;
        private DataGridView gridFindings, gridManual;
        private ProgressBar progress;
        private readonly ToolTip tips = new ToolTip();

        public MainForm() : this(true) { }

        public MainForm(bool persist)
        {
            this.persist = persist;
            Text = AppInfo.Name;
            Font = new Font("Segoe UI", 9F);
            AutoScaleMode = AutoScaleMode.Dpi;
            StartPosition = FormStartPosition.CenterScreen;
            Size = new Size(1180, 800);
            MinimumSize = new Size(940, 620);
            BackColor = Color.White;
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
            BuildUi();
            saveTimer.Tick += (s, e) => { saveTimer.Stop(); SaveDraft(); };
            settings = AppSettings.Load();
            chkDeep.Checked = settings.DeepAudit;
            chkOnline.Checked = settings.OnlineUpdateScan;
        }

        // ------------------------------------------------------------ fitting the screen

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);   // DPI scaling is applied here, so measure afterwards
            if (persist) FitToScreen(this, true);
        }

        /// <summary>
        /// Keeps a window inside the screen's working area (laptops, 125-150 % scaling), so the
        /// bottom buttons are never off-screen. A resizable window that does not fit is maximized.
        /// </summary>
        internal static void FitToScreen(Form f, bool maximizeIfTooBig)
        {
            Rectangle area = Screen.FromPoint(f.StartPosition == FormStartPosition.CenterParent && f.Owner != null ? f.Owner.Location : Cursor.Position).WorkingArea;
            f.MinimumSize = new Size(Math.Min(f.MinimumSize.Width, area.Width), Math.Min(f.MinimumSize.Height, area.Height));
            bool tooBig = f.Width > area.Width || f.Height > area.Height;
            if (!tooBig) return;
            if (maximizeIfTooBig) { f.WindowState = FormWindowState.Maximized; return; }
            f.Size = new Size(Math.Min(f.Width, area.Width), Math.Min(f.Height, area.Height));
            f.Location = new Point(area.Left + (area.Width - f.Width) / 2, area.Top + (area.Height - f.Height) / 2);
        }

        /// <summary>Test mode: resize the window, for checking small screens.</summary>
        internal void ResizeForTest(Size size) { MinimumSize = new Size(0, 0); Size = size; PerformLayout(); Application.DoEvents(); }

        // ------------------------------------------------------------ UI construction

        private static Button NewButton(string text, bool primary)
        {
            var b = new Button
            {
                Text = text, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Padding = new Padding(10, 4, 10, 4),
                Margin = new Padding(4, 6, 4, 6), FlatStyle = FlatStyle.Flat, Cursor = Cursors.Hand,
                BackColor = primary ? Accent : Color.White, ForeColor = primary ? Color.White : Color.FromArgb(17, 24, 39)
            };
            b.FlatAppearance.BorderColor = primary ? Accent : Color.FromArgb(209, 213, 219);
            if (primary) b.Font = new Font("Segoe UI", 9.5F, FontStyle.Bold);
            return b;
        }

        internal static DataGridView NewGrid()
        {
            var g = new DataGridView
            {
                Dock = DockStyle.Fill, AllowUserToAddRows = false, AllowUserToDeleteRows = false, AllowUserToResizeRows = false,
                RowHeadersVisible = false, SelectionMode = DataGridViewSelectionMode.CellSelect, MultiSelect = false,
                AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.AllCells, AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
                BackgroundColor = Color.White, BorderStyle = BorderStyle.None, GridColor = Border, EnableHeadersVisualStyles = false,
                CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal, EditMode = DataGridViewEditMode.EditOnEnter,
                ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize
            };
            g.DefaultCellStyle.WrapMode = DataGridViewTriState.True;
            g.DefaultCellStyle.Padding = new Padding(4, 5, 4, 5);
            g.DefaultCellStyle.SelectionBackColor = Color.FromArgb(219, 234, 254);
            g.DefaultCellStyle.SelectionForeColor = Color.FromArgb(17, 24, 39);
            g.ColumnHeadersDefaultCellStyle.BackColor = Soft;
            g.ColumnHeadersDefaultCellStyle.ForeColor = MutedText;
            g.ColumnHeadersDefaultCellStyle.Font = new Font("Segoe UI", 8.5F, FontStyle.Bold);
            g.ColumnHeadersDefaultCellStyle.Padding = new Padding(4, 6, 4, 6);
            g.ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.None;
            return g;
        }

        private static DataGridViewTextBoxColumn TextCol(string header, float weight, bool readOnly)
        {
            return new DataGridViewTextBoxColumn { HeaderText = header, FillWeight = weight, ReadOnly = readOnly, SortMode = DataGridViewColumnSortMode.NotSortable };
        }

        private void BuildUi()
        {
            // Header band
            var header = new Panel { Dock = DockStyle.Top, Height = 78, BackColor = Navy, Padding = new Padding(20, 10, 20, 8) };
            int textLeft = 20;
            var controls = new List<Control>();
            if (AppInfo.Logo != null)
            {
                // Polarnite logo (white wordmark + badge) on the navy band; text starts to its right.
                int logoH = 56, logoW = (int)Math.Round(logoH * (double)AppInfo.Logo.Width / AppInfo.Logo.Height);
                controls.Add(new PictureBox { Image = AppInfo.Logo, SizeMode = PictureBoxSizeMode.Zoom, Size = new Size(logoW, logoH), Location = new Point(16, 11), BackColor = Navy });
                var divider = new Panel { BackColor = Color.FromArgb(51, 78, 110), Size = new Size(1, 50), Location = new Point(16 + logoW + 16, 14) };
                controls.Add(divider);
                textLeft = 16 + logoW + 34;
            }
            var titleSmall = new Label { Text = "MONTHLY SERVER AUDIT", ForeColor = SkySoft, Font = new Font("Segoe UI", 8F, FontStyle.Bold), AutoSize = true, Location = new Point(textLeft, 10) };
            lblServer = new Label { Text = Environment.MachineName, ForeColor = Color.White, Font = new Font("Segoe UI Semibold", 17F), AutoSize = true, Location = new Point(textLeft - 2, 26) };
            lblSub = new Label { Text = "No audit loaded", ForeColor = SlateText, AutoSize = true, Location = new Point(textLeft + 1, 56) };
            lblPill = new Label { Text = "", AutoSize = true, ForeColor = Color.White, Font = new Font("Segoe UI", 9F, FontStyle.Bold), Padding = new Padding(12, 5, 12, 5), Anchor = AnchorStyles.Top | AnchorStyles.Right, Visible = false };
            controls.AddRange(new Control[] { titleSmall, lblServer, lblSub, lblPill });
            header.Controls.AddRange(controls.ToArray());
            header.Resize += (s, e) => lblPill.Location = new Point(header.ClientSize.Width - lblPill.Width - 22, 26);
            lblPill.SizeChanged += (s, e) => lblPill.Location = new Point(header.ClientSize.Width - lblPill.Width - 22, 26);
            var stripe = new Panel { Dock = DockStyle.Top, Height = 3, BackColor = Color.FromArgb(56, 189, 248) };

            // Toolbar
            var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 46, BackColor = Soft, Padding = new Padding(14, 0, 14, 0), WrapContents = false };
            btnRun = NewButton("▶  Run audit", false);
            btnCancel = NewButton("Cancel", false); btnCancel.Enabled = false;
            btnOpen = NewButton("Open report…", false);
            btnSettings = NewButton("Settings && schedule…", false);
            chkDeep = new CheckBox { Text = "Deep audit (DC / server roles)", AutoSize = true, Margin = new Padding(18, 13, 4, 4) };
            chkOnline = new CheckBox { Text = "Online update scan", AutoSize = true, Margin = new Padding(8, 13, 4, 4) };
            btnUpdate = NewButton("Check for updates", false);
            btnNinja = NewButton("NinjaOne…", false);
            toolbar.Controls.AddRange(new Control[] { btnRun, btnCancel, btnOpen, btnNinja, btnSettings, btnUpdate, chkDeep, chkOnline });
            tips.SetToolTip(btnNinja, "Sign in to NinjaOne and pull this server's alerts, patches, antivirus, organization and warranty into the audit. Read-only; the sign-in lasts until the app closes.");
            tips.SetToolTip(btnUpdate, "This build: " + Updater.CurrentBuiltText + ". Downloads the newest version from GitHub and restarts the app.");
            tips.SetToolTip(chkDeep, "Adds AD, DNS, DHCP, certificate and storage-usage checks. Takes several minutes longer.");
            tips.SetToolTip(chkOnline, "Contacts Windows Update / WSUS for a current missing-updates list (90 s limit). Nothing is installed.");

            lblBanner = new Label { Dock = DockStyle.Top, AutoSize = false, Height = 34, Padding = new Padding(18, 0, 18, 0), TextAlign = ContentAlignment.MiddleLeft, Visible = false, Font = new Font("Segoe UI", 9F, FontStyle.Bold) };

            // Bottom bar
            var bottom = new Panel { Dock = DockStyle.Bottom, Height = 64, BackColor = Soft, Padding = new Padding(16, 8, 16, 8) };
            progress = new ProgressBar { Width = 200, Height = 14, Location = new Point(18, 22), Visible = false, Maximum = 80 };
            lblProgress = new Label { AutoSize = true, Location = new Point(226, 20), ForeColor = MutedText, Text = "Ready." };
            var right = new FlowLayoutPanel { Dock = DockStyle.Right, AutoSize = true, WrapContents = false, FlowDirection = FlowDirection.LeftToRight };
            lblReady = new Label { AutoSize = true, Margin = new Padding(4, 12, 12, 4), Font = new Font("Segoe UI", 9F, FontStyle.Bold) };
            btnPreview = NewButton("Preview PDF", false);
            btnSubmit = NewButton("Submit ticket  ✉", true);
            right.Controls.AddRange(new Control[] { lblReady, btnPreview, btnSubmit });
            bottom.Controls.AddRange(new Control[] { progress, lblProgress, right });

            // Tabs
            tabs = new TabControl { Dock = DockStyle.Fill, Padding = new Point(16, 6) };
            tabOverview = new TabPage("Overview") { BackColor = Color.White, Padding = new Padding(14) };
            tabFindings = new TabPage("Findings") { BackColor = Color.White, Padding = new Padding(10) };
            tabManual = new TabPage("Manual checks") { BackColor = Color.White, Padding = new Padding(10) };
            tabLog = new TabPage("Collection log") { BackColor = Color.White, Padding = new Padding(10) };
            tabs.TabPages.AddRange(new[] { tabOverview, tabFindings, tabManual, tabLog });
            BuildOverview();
            BuildFindings();
            BuildManual();
            txtLog = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Font = new Font("Consolas", 9F), BackColor = Color.White, BorderStyle = BorderStyle.None };
            tabLog.Controls.Add(txtLog);

            Controls.Add(tabs);
            Controls.Add(lblBanner);
            Controls.Add(toolbar);
            Controls.Add(stripe);
            Controls.Add(header);
            Controls.Add(bottom);

            btnRun.Click += (s, e) => RunAudit();
            btnCancel.Click += (s, e) => { if (cts != null) { cts.Cancel(); btnCancel.Enabled = false; lblProgress.Text = "Cancelling…"; } };
            btnOpen.Click += (s, e) => OpenReport();
            btnSettings.Click += (s, e) => OpenSettings();
            btnUpdate.Click += (s, e) => UpdateApp();
            btnNinja.Click += (s, e) => PullNinja(true);
            btnPreview.Click += (s, e) => PreviewPdf();
            btnSubmit.Click += (s, e) => Submit();
            UpdateEnabled();
        }

        private void BuildOverview()
        {
            var split = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1 };
            split.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 46));
            split.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 54));

            var form = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new Padding(0, 0, 18, 0) };
            Func<string, Label> heading = t => new Label { Text = t, AutoSize = true, Font = new Font("Segoe UI Semibold", 11F), Margin = new Padding(0, 4, 0, 8) };
            Func<string, Label> caption = t => new Label { Text = t, AutoSize = true, ForeColor = MutedText, Font = new Font("Segoe UI", 8.5F, FontStyle.Bold), Margin = new Padding(0, 8, 0, 2) };
            txtTenant = new TextBox { Dock = DockStyle.Top };
            txtTech = new TextBox { Dock = DockStyle.Top };
            txtPurpose = new TextBox { Dock = DockStyle.Top };
            txtSummary = new TextBox { Dock = DockStyle.Fill, Multiline = true, ScrollBars = ScrollBars.Vertical, MinimumSize = new Size(0, 90) };
            lblSubject = new Label { AutoSize = true, ForeColor = MutedText, Margin = new Padding(0, 10, 0, 0), MaximumSize = new Size(480, 0) };
            form.Controls.Add(heading("Ticket details"));
            form.Controls.Add(caption("TENANT / CLIENT NAME *"));
            form.Controls.Add(txtTenant);
            form.Controls.Add(caption("TECHNICIAN *"));
            form.Controls.Add(txtTech);
            form.Controls.Add(caption("SERVER ROLE / PURPOSE"));
            form.Controls.Add(txtPurpose);
            form.Controls.Add(caption("SUMMARY NOTES FOR THE TICKET AND REPORT"));
            form.Controls.Add(txtSummary);
            form.Controls.Add(lblSubject);
            for (int i = 0; i < form.Controls.Count; i++) form.RowStyles.Add(new RowStyle(form.Controls[i] == txtSummary ? SizeType.Percent : SizeType.AutoSize, 100));
            tips.SetToolTip(txtTenant, "Used in the email subject, the PDF and the file name. Pre-filled from the Entra tenant (device join or Microsoft 365 sign-in), else the AD domain. A name you type here is kept.");
            tips.SetToolTip(txtPurpose, "For example: Domain controller / file server. Carried forward to next month.");

            var rightPane = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3 };
            rightPane.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            rightPane.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            rightPane.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            lblCounts = new Label { AutoSize = true, Font = new Font("Segoe UI", 9.5F), Margin = new Padding(0, 0, 0, 8) };
            lvSnapshot = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, HeaderStyle = ColumnHeaderStyle.None, BorderStyle = BorderStyle.None };
            lvSnapshot.Columns.Add("Item", 140);
            lvSnapshot.Columns.Add("Value", 440);
            lvSnapshot.Resize += (s, e) => { if (lvSnapshot.Columns.Count == 2) lvSnapshot.Columns[1].Width = Math.Max(200, lvSnapshot.ClientSize.Width - lvSnapshot.Columns[0].Width - 4); };
            rightPane.Controls.Add(heading("Server snapshot"), 0, 0);
            rightPane.Controls.Add(lblCounts, 0, 1);
            rightPane.Controls.Add(lvSnapshot, 0, 2);

            split.Controls.Add(form, 0, 0);
            split.Controls.Add(rightPane, 1, 0);
            tabOverview.Controls.Add(split);

            EventHandler changed = (s, e) =>
            {
                if (loading || draft == null) return;
                draft.Tenant = txtTenant.Text;
                draft.Technician = txtTech.Text;
                draft.ServerPurpose = txtPurpose.Text;
                draft.Summary = txtSummary.Text;
                UpdateSubject();
                Changed();
            };
            txtTenant.TextChanged += changed;
            txtTenant.TextChanged += (s, e) => { if (!loading && draft != null) draft.TenantSource = "Technician"; };
            txtTech.TextChanged += changed;
            txtPurpose.TextChanged += changed;
            txtSummary.TextChanged += changed;
        }

        private void BuildFindings()
        {
            gridFindings = NewGrid();
            var rating = new DataGridViewComboBoxColumn { HeaderText = "RATING", FillWeight = 11, FlatStyle = FlatStyle.Flat, DisplayStyle = DataGridViewComboBoxDisplayStyle.DropDownButton, SortMode = DataGridViewColumnSortMode.NotSortable };
            rating.Items.AddRange(OverrideStore.Ratings);
            gridFindings.Columns.Add(rating);
            gridFindings.Columns.Add(TextCol("AREA", 9, true));
            gridFindings.Columns.Add(TextCol("FINDING", 26, true));
            gridFindings.Columns.Add(TextCol("DETAIL", 38, true));
            gridFindings.Columns.Add(TextCol("TECHNICIAN NOTE (optional, shown on the report)", 24, false));
            gridFindings.Columns[2].DefaultCellStyle.Font = new Font("Segoe UI", 9F, FontStyle.Bold);
            gridFindings.Columns[3].DefaultCellStyle.ForeColor = Color.FromArgb(75, 85, 99);
            gridFindings.Columns[4].DefaultCellStyle.BackColor = Color.FromArgb(248, 250, 252);
            gridFindings.CellFormatting += (s, e) =>
            {
                if (e.ColumnIndex != 0 || e.RowIndex < 0) return;
                Finding f = gridFindings.Rows[e.RowIndex].Tag as Finding;
                if (f == null) return;
                e.CellStyle.BackColor = TintColor(f.Severity);
                e.CellStyle.ForeColor = InkColor(f.Severity);
                e.CellStyle.SelectionBackColor = e.CellStyle.BackColor;
                e.CellStyle.SelectionForeColor = e.CellStyle.ForeColor;
                e.CellStyle.Font = new Font("Segoe UI", 8.5F, FontStyle.Bold);
            };
            gridFindings.CurrentCellDirtyStateChanged += (s, e) =>
            {
                if (gridFindings.IsCurrentCellDirty && gridFindings.CurrentCell is DataGridViewComboBoxCell) gridFindings.CommitEdit(DataGridViewDataErrorContexts.Commit);
            };
            gridFindings.DataError += (s, e) => { e.ThrowException = false; };
            gridFindings.CellValueChanged += (s, e) =>
            {
                if (loading || e.RowIndex < 0 || draft == null) return;
                Finding f = gridFindings.Rows[e.RowIndex].Tag as Finding;
                if (f == null) return;
                if (e.ColumnIndex == 4)
                {
                    string note = Convert.ToString(gridFindings.Rows[e.RowIndex].Cells[4].Value);
                    draft.FindingNotes[f.Key] = note;
                    var all = OverrideStore.Load();
                    FindingOverride o;
                    if (all.TryGetValue(f.Key, out o)) { o.Reason = note ?? ""; OverrideStore.Save(all); f.OverrideReason = o.Reason; }
                    Changed();
                }
                else if (e.ColumnIndex == 0)
                {
                    string chosen = Convert.ToString(gridFindings.Rows[e.RowIndex].Cells[0].Value);
                    BeginInvoke(new Action(() => SetRating(f, chosen)));
                }
            };
            var findingsBar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = false, Padding = new Padding(0, 0, 0, 4) };
            chkShowPassed = new CheckBox { Text = "Show passed checks", AutoSize = true, Margin = new Padding(2, 6, 18, 4) };
            chkShowPassed.CheckedChanged += (s, e) => FillFindings();
            lblOverrides = new Label { AutoSize = true, ForeColor = MutedText, Margin = new Padding(0, 7, 8, 4),
                Text = "Change RATING to override a result for this server (for example Accepted when a client has no Huntress licence). It is remembered for future audits." };
            btnResetOverrides = new Button { Text = "Reset overrides", AutoSize = true, FlatStyle = FlatStyle.Flat, Margin = new Padding(0, 2, 0, 2), Visible = false };
            btnResetOverrides.FlatAppearance.BorderColor = Color.FromArgb(209, 213, 219);
            btnResetOverrides.Click += (s, e) => ResetOverrides();
            findingsBar.Controls.AddRange(new Control[] { chkShowPassed, lblOverrides, btnResetOverrides });
            tabFindings.Controls.Add(gridFindings);
            tabFindings.Controls.Add(findingsBar);
        }

        private void BuildManual()
        {
            gridManual = NewGrid();
            gridManual.Columns.Add(TextCol("AREA", 9, true));
            gridManual.Columns.Add(TextCol("CHECK", 30, true));
            gridManual.Columns.Add(TextCol("", 8, true));
            var status = new DataGridViewComboBoxColumn { HeaderText = "STATUS", FillWeight = 11, FlatStyle = FlatStyle.Flat, DisplayStyle = DataGridViewComboBoxDisplayStyle.DropDownButton };
            status.Items.AddRange(ManualCatalog.Statuses.Cast<object>().ToArray());
            gridManual.Columns.Add(status);
            gridManual.Columns.Add(TextCol("NOTES", 28, false));
            gridManual.Columns.Add(TextCol("LAST MONTH", 16, true));
            gridManual.Columns[1].DefaultCellStyle.Font = new Font("Segoe UI", 9F, FontStyle.Bold);
            gridManual.Columns[2].DefaultCellStyle.ForeColor = MutedText;
            gridManual.Columns[5].DefaultCellStyle.ForeColor = MutedText;
            gridManual.Columns[4].DefaultCellStyle.BackColor = Color.FromArgb(248, 250, 252);
            gridManual.CurrentCellDirtyStateChanged += (s, e) =>
            {
                if (gridManual.IsCurrentCellDirty && gridManual.CurrentCell is DataGridViewComboBoxCell) gridManual.CommitEdit(DataGridViewDataErrorContexts.Commit);
            };
            gridManual.CellFormatting += (s, e) =>
            {
                if (e.ColumnIndex != 3 || e.RowIndex < 0) return;
                Severity sev = ReportPdf.ManualSeverity(Convert.ToString(e.Value));
                if (Convert.ToString(e.Value) == ManualCatalog.NotChecked)
                {
                    bool required = Convert.ToString(gridManual.Rows[e.RowIndex].Cells[2].Value) == "Required";
                    e.CellStyle.BackColor = required ? Color.FromArgb(254, 243, 199) : Color.White;
                    e.CellStyle.ForeColor = required ? Color.FromArgb(180, 83, 9) : MutedText;
                }
                else { e.CellStyle.BackColor = TintColor(sev); e.CellStyle.ForeColor = InkColor(sev); }
                e.CellStyle.SelectionBackColor = e.CellStyle.BackColor;
                e.CellStyle.SelectionForeColor = e.CellStyle.ForeColor;
            };
            gridManual.CellValueChanged += (s, e) =>
            {
                if (loading || e.RowIndex < 0 || draft == null) return;
                string id = gridManual.Rows[e.RowIndex].Tag as string;
                if (id == null) return;
                ManualAnswer ans = draft.Answer(id);
                if (e.ColumnIndex == 3) ans.Status = Convert.ToString(gridManual.Rows[e.RowIndex].Cells[3].Value);
                else if (e.ColumnIndex == 4) ans.Notes = Convert.ToString(gridManual.Rows[e.RowIndex].Cells[4].Value);
                else return;
                ans.AutoSet = false; // the technician's answer now stands
                gridManual.InvalidateRow(e.RowIndex);
                Changed();
            };
            gridManual.DataError += (s, e) => { e.ThrowException = false; };
            var hint = new Label
            {
                Dock = DockStyle.Top, AutoSize = false, Height = 40, ForeColor = MutedText, Padding = new Padding(2, 0, 0, 8),
                Text = "Things the server can't fully report on itself. Items marked \"Auto-verified\" were answered from collected evidence; change them if the console says otherwise. Everything here is optional: unanswered items are sent as \"Not checked\"."
            };
            tabManual.Controls.Add(gridManual);
            tabManual.Controls.Add(hint);
        }

        internal static Color TintColor(Severity s)
        {
            switch (s)
            {
                case Severity.Critical: return Color.FromArgb(254, 226, 226);
                case Severity.Warning: return Color.FromArgb(254, 243, 199);
                case Severity.Info: return Color.FromArgb(219, 234, 254);
                case Severity.Pass: return Color.FromArgb(220, 252, 231);
                default: return Color.FromArgb(243, 244, 246);
            }
        }

        internal static Color InkColor(Severity s)
        {
            switch (s)
            {
                case Severity.Critical: return Color.FromArgb(185, 28, 28);
                case Severity.Warning: return Color.FromArgb(180, 83, 9);
                case Severity.Info: return Color.FromArgb(29, 78, 216);
                case Severity.Pass: return Color.FromArgb(21, 128, 61);
                default: return Color.FromArgb(75, 85, 99);
            }
        }

        private static Color StrongColor(Severity s)
        {
            switch (s)
            {
                case Severity.Critical: return Color.FromArgb(220, 38, 38);
                case Severity.Warning: return Color.FromArgb(217, 119, 6);
                default: return Color.FromArgb(22, 163, 74);
            }
        }

        // ------------------------------------------------------------ lifecycle

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            if (!persist) return;
            try
            {
                AppPaths.EnsureRoot();
                lastAnswers = DraftStore.LoadLastAnswers();
                DraftState d = DraftStore.Load();
                if (d != null && File.Exists(d.ReportPath))
                {
                    report = AuditReport.Load(d.ReportPath);
                    analysis = Workflow.Analyze(report, settings);
                    draft = d;
                    if (!draft.IsSubmitted) draft.ApplyAuto(analysis);
                    Populate();
                    tabs.SelectedTab = d.IsSubmitted ? tabOverview : tabManual;
                }
                else
                {
                    lblProgress.Text = "No audit yet. Click Run audit to collect this server's data.";
                }
            }
            catch (Exception ex)
            {
                Log.Write("Startup load failed: " + ex);
                lblProgress.Text = "Could not load the saved draft: " + ex.Message;
            }
            CheckForUpdateQuietly();
        }

        // ------------------------------------------------------------ updates

        private void CheckForUpdateQuietly()
        {
            Task.Factory.StartNew(() => Updater.Check()).ContinueWith(t =>
            {
                if (IsDisposed) return;
                if (t.IsFaulted) { Log.Write("Update check failed: " + t.Exception.GetBaseException().Message); return; }
                if (!Updater.IsNewer(t.Result)) return;
                btnUpdate.Text = "Update available  \u2193";
                btnUpdate.BackColor = Color.FromArgb(254, 243, 199);
                btnUpdate.FlatAppearance.BorderColor = Color.FromArgb(217, 119, 6);
                btnUpdate.Font = new Font("Segoe UI", 9F, FontStyle.Bold);
                tips.SetToolTip(btnUpdate, "Build " + t.Result.BuiltText + " is on GitHub (this build: " + Updater.CurrentBuiltText + "). Click to download it and restart.");
            }, TaskScheduler.FromCurrentSynchronizationContext());
        }

        private async void UpdateApp()
        {
            if (busy) { MessageBox.Show(this, "Wait for the current operation to finish first.", AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
            btnUpdate.Enabled = false;
            string before = lblProgress.Text;
            try
            {
                lblProgress.Text = "Checking GitHub for a newer version…";
                UpdateInfo u = await Task.Run(() => Updater.Check());
                if (!Updater.IsNewer(u))
                {
                    lblProgress.Text = before;
                    MessageBox.Show(this, "You have the latest version (built " + Updater.CurrentBuiltText + ").", AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                if (MessageBox.Show(this, "A newer version is on GitHub.\n\nNew build: " + u.BuiltText + " (collector " + u.Collector + ")\nThis build: " + Updater.CurrentBuiltText +
                        "\n\nDownload it and restart the app now? Your draft is saved first.", AppInfo.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                {
                    lblProgress.Text = before;
                    return;
                }
                lblProgress.Text = "Downloading the update…";
                string file = await Task.Run(() => Updater.Download(u));
                SaveDraft();
                Updater.InstallAndStart(file, true);
                Close();
            }
            catch (Exception ex)
            {
                Log.Write("Update failed: " + ex);
                lblProgress.Text = before;
                MessageBox.Show(this, "The update did not complete:\n\n" + ex.Message, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally { if (!IsDisposed) btnUpdate.Enabled = !busy; }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (busy)
            {
                if (MessageBox.Show(this, "An operation is still running. Cancel it and close?", AppInfo.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                {
                    e.Cancel = true;
                    return;
                }
                if (cts != null) cts.Cancel();
            }
            SaveDraft();
            base.OnFormClosing(e);
        }

        /// <summary>Loads a report for screenshots/tests without touching saved state.</summary>
        public void LoadForPreview(string reportPath, DraftState d)
        {
            report = AuditReport.Load(reportPath);
            analysis = Workflow.Analyze(report, settings);
            draft = d ?? DraftStore.NewDraft(reportPath, analysis, settings, "Manual");
            draft.ApplyAuto(analysis);
            Populate();
        }

        private void LoadReport(string path, string source)
        {
            try
            {
                report = AuditReport.Load(path);
                analysis = Workflow.Analyze(report, settings);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Could not read the audit report:\n\n" + ex.Message, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            DraftState existing = persist ? DraftStore.Load() : draft;
            if (existing != null && !existing.IsSubmitted && existing.MonthKey == analysis.MonthKey)
            {
                draft = existing;
                draft.ReportPath = path;
                draft.Source = source;
            }
            else if (existing != null && string.Equals(existing.ReportPath, path, StringComparison.OrdinalIgnoreCase))
                draft = existing;
            else
                draft = DraftStore.NewDraft(path, analysis, settings, source);
            if (string.IsNullOrWhiteSpace(draft.Technician)) draft.Technician = settings.LastTechnician;
            if (!draft.IsSubmitted) draft.ApplyAuto(analysis);
            SaveDraft();
            Populate();
            if (persist && (Ninja.SignedIn || Ninja.RememberedUntil.HasValue || Ninja.HasServiceKey)) BeginInvoke(new Action(() => PullNinja(false)));
        }

        // ------------------------------------------------------------ NinjaOne

        /// <summary>Signs in if needed, then pulls this server's NinjaOne data into the audit.</summary>
        private async void PullNinja(bool interactive)
        {
            if (ninjaCts != null) { ninjaCts.Cancel(); return; }   // second click while signing in = cancel
            if (report == null || analysis == null)
            {
                if (interactive) MessageBox.Show(this, "Run or open an audit first.", AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            if (busy) return;
            string before = lblProgress.Text;
            ninjaCts = new CancellationTokenSource();
            CancellationToken ct = ninjaCts.Token;
            btnNinja.Text = "Cancel NinjaOne";
            Action<string> status = m => { if (!IsDisposed) BeginInvoke(new Action(() => lblProgress.Text = m)); };
            try
            {
                if (!Ninja.SignedIn && !await Task.Run(() => Ninja.TryResume()))
                {
                    if (!interactive) return;
                    bool remember;
                    if (!AskNinjaSignIn(out remember)) return;
                    string host = settings.NinjaHost, client = settings.NinjaClientId;
                    await Task.Run(() => Ninja.SignIn(host, client, remember, ct, status));
                    Activate();
                }
                string name = analysis.ServerName;
                string serial = J.Str(report.Check("MachineIdentity").Data.FirstOrDefault(d => J.Get(d, "SerialNumber") != null), "SerialNumber");
                Dictionary<string, object> data = await Task.Run(() => Ninja.Fetch(name, serial, status));
                JsonFile.Write(Ninja.SidecarPath(report.Path), data);
                Reanalyze();
                bool matched = J.Bool(data, "Matched") == true;
                lblProgress.Text = matched ? "NinjaOne data added (" + J.Str(data, "MatchedBy") + ")." : "NinjaOne: " + J.Str(data, "MatchNote");
                if (interactive && !matched) MessageBox.Show(this, J.Str(data, "MatchNote"), AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            catch (OperationCanceledException) { lblProgress.Text = before; }
            catch (Exception ex)
            {
                Log.Write("NinjaOne: " + ex);
                lblProgress.Text = before;
                if (interactive) MessageBox.Show(this, "NinjaOne: " + ex.Message, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally
            {
                ninjaCts.Dispose(); ninjaCts = null;
                if (!IsDisposed) btnNinja.Text = Ninja.SignedIn || Ninja.RememberedUntil.HasValue || Ninja.HasServiceKey ? "Refresh NinjaOne" : "NinjaOne…";
            }
        }

        /// <summary>Asks before opening the NinjaOne sign-in, with the opt-in "remember for 30 days" box.</summary>
        private bool AskNinjaSignIn(out bool remember)
        {
            remember = false;
            using (var dlg = new Form { Text = "Sign in to NinjaOne", FormBorderStyle = FormBorderStyle.FixedDialog, MaximizeBox = false, MinimizeBox = false,
                                        StartPosition = FormStartPosition.CenterParent, AutoScaleMode = AutoScaleMode.Dpi, Font = Font, ClientSize = new Size(470, 210), BackColor = Color.White })
            {
                var text = new Label { Location = new Point(18, 16), Size = new Size(434, 54),
                    Text = "Your browser opens the NinjaOne sign-in. Sign in with your own NinjaOne account; the app then reads this server's alerts, patches, antivirus and organization (read-only)." };
                var chk = new CheckBox { Location = new Point(18, 78), AutoSize = true, Text = "Remember my sign-in on this server for " + Ninja.RememberDays + " days" };
                var note = new Label { Location = new Point(36, 102), Size = new Size(416, 50), ForeColor = MutedText,
                    Text = "Later audits and scheduled runs then pull NinjaOne data without a sign-in. Anyone with administrator rights on this server could use it to read NinjaOne data until it expires. Remove it any time with Forget in Settings." };
                var ok = new Button { Text = "Sign in", DialogResult = DialogResult.OK, Location = new Point(276, 166), Size = new Size(86, 30) };
                var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Location = new Point(368, 166), Size = new Size(86, 30) };
                dlg.Controls.AddRange(new Control[] { text, chk, note, ok, cancel });
                dlg.AcceptButton = ok; dlg.CancelButton = cancel;
                if (dlg.ShowDialog(this) != DialogResult.OK) return false;
                remember = chk.Checked;
                return true;
            }
        }

        private void Changed()
        {
            if (loading) return;
            saveTimer.Stop();
            saveTimer.Start();
            UpdateReadiness();
        }

        private void SaveDraft()
        {
            if (!persist || draft == null) return;
            try { DraftStore.Save(draft); }
            catch (Exception ex) { Log.Write("Draft save failed: " + ex.Message); }
        }

        // ------------------------------------------------------------ populate

        private void Populate()
        {
            loading = true;
            try
            {
                lblServer.Text = analysis.ServerName;
                lblSub.Text = (string.IsNullOrWhiteSpace(draft.Tenant) ? "" : draft.Tenant + "   ·   ") + analysis.MonthLabel + "   ·   audited " + J.FormatDateTime(analysis.AuditTime);
                Text = AppInfo.Name + " — " + analysis.ServerName;
                txtTenant.Text = draft.Tenant;
                txtTech.Text = draft.Technician;
                txtPurpose.Text = draft.ServerPurpose;
                txtSummary.Text = draft.Summary;

                lvSnapshot.Items.Clear();
                foreach (var kv in analysis.Snapshot.Items)
                {
                    var item = new ListViewItem(kv.Key) { ForeColor = MutedText };
                    item.SubItems.Add(kv.Value);
                    item.UseItemStyleForSubItems = false;
                    item.SubItems[1].ForeColor = Color.FromArgb(17, 24, 39);
                    lvSnapshot.Items.Add(item);
                }
                lblCounts.Text = analysis.Count(Severity.Critical) + " critical   ·   " + analysis.Count(Severity.Warning) + " warnings   ·   " +
                                 analysis.Count(Severity.Info) + " best practice   ·   " + analysis.Count(Severity.Pass) + " passed" + (analysis.Count(Severity.Accepted) > 0 ? "   ·   " + analysis.Count(Severity.Accepted) + " accepted" : "") +
                                 (analysis.Coverage.Rows.Count > 0 ? "   ·   " + analysis.Coverage.Rows.Count + " checks without data" : "");
                FillFindings();
                FillManual();
                UpdateSubject();
                UpdateBanner();
                UpdatePill();
            }
            finally { loading = false; }
            UpdateReadiness();
            UpdateEnabled();
        }

        private void FillFindings()
        {
            if (analysis == null) return;
            bool wasLoading = loading;
            loading = true;
            gridFindings.Rows.Clear();
            foreach (Finding f in analysis.Findings.Where(x => chkShowPassed.Checked || x.Severity != Severity.Pass || x.OriginalSeverity.HasValue))
            {
                string note;
                draft.FindingNotes.TryGetValue(f.Key, out note);
                string detail = f.Detail + (f.OriginalSeverity.HasValue ? (f.Detail.Length > 0 ? "\n" : "") + "Overridden: was " + Sev.Label(f.OriginalSeverity.Value) + (f.OverrideBy.Length > 0 ? ", changed by " + f.OverrideBy : "") : "");
                int i = gridFindings.Rows.Add(Sev.Label(f.Severity), f.Area, f.Title + (f.IsNew ? "  \u2022 NEW" : ""), detail, note ?? "");
                gridFindings.Rows[i].Tag = f;
            }
            int overridden = analysis.Findings.Count(x => x.OriginalSeverity.HasValue);
            btnResetOverrides.Text = "Reset overrides (" + overridden + ")";
            btnResetOverrides.Visible = overridden > 0;
            gridFindings.CurrentCell = null;   // don't open the first rating in edit mode
            loading = wasLoading;
        }

        /// <summary>Saves a technician rating for this finding (remembered on this server) and re-rates the audit.</summary>
        private void SetRating(Finding f, string chosen)
        {
            if (report == null || draft == null || string.IsNullOrEmpty(chosen)) return;
            Severity original = f.OriginalSeverity ?? f.Severity;
            var all = OverrideStore.Load();
            if (chosen == Sev.Label(original)) all.Remove(f.Key);
            else
            {
                string note;
                draft.FindingNotes.TryGetValue(f.Key, out note);
                all[f.Key] = new FindingOverride { Key = f.Key, Rating = chosen, Reason = note ?? "", Title = f.Title,
                    By = string.IsNullOrWhiteSpace(txtTech.Text) ? Environment.UserName : txtTech.Text.Trim(), At = DateTime.Now.ToString("o", CultureInfo.InvariantCulture) };
            }
            try { OverrideStore.Save(all); }
            catch (Exception ex) { MessageBox.Show(this, "Could not save the override:\n\n" + ex.Message, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
            Reanalyze();
        }

        private void ResetOverrides()
        {
            int n = analysis == null ? 0 : analysis.Findings.Count(x => x.OriginalSeverity.HasValue);
            if (MessageBox.Show(this, "Remove all " + n + " rating overrides for this server? Findings go back to the app's own ratings.", AppInfo.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            try { OverrideStore.Save(new Dictionary<string, FindingOverride>()); }
            catch (Exception ex) { MessageBox.Show(this, ex.Message, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            Reanalyze();
        }

        private void Reanalyze()
        {
            if (report == null) return;
            report = AuditReport.Load(report.Path);   // picks up NinjaOne data saved next to it
            int row = gridFindings.FirstDisplayedScrollingRowIndex;
            analysis = Workflow.Analyze(report, settings);
            if (draft != null && !draft.IsSubmitted) draft.ApplyAuto(analysis);
            Populate();
            if (row >= 0 && row < gridFindings.Rows.Count) gridFindings.FirstDisplayedScrollingRowIndex = row;
            Changed();
        }

        private void FillManual()
        {
            gridManual.Rows.Clear();
            foreach (ManualItemDef item in ManualCatalog.For(analysis))
            {
                ManualAnswer ans = draft.Answer(item.Id);
                string last = "";
                if (lastAnswers != null && lastAnswers.Manual.ContainsKey(item.Id))
                {
                    ManualAnswer prev = lastAnswers.Manual[item.Id];
                    last = prev.Status + (string.IsNullOrWhiteSpace(prev.Notes) ? "" : " — " + J.Shorten(prev.Notes, 70));
                }
                int i = gridManual.Rows.Add(item.Area, item.Title, item.Required ? "Required" : "Optional", ans.Status, ans.Notes, last);
                gridManual.Rows[i].Tag = item.Id;
                gridManual.Rows[i].Cells[1].ToolTipText = item.Guidance;
                gridManual.Rows[i].Cells[4].ToolTipText = item.Guidance;
            }
        }

        private void UpdateSubject()
        {
            if (analysis == null || draft == null) { lblSubject.Text = ""; return; }
            lblSubject.Text = "Ticket to " + settings.ToAddress + "\nSubject: " + TicketComposer.Subject(settings, analysis, draft) +
                              "\nAttachment: " + TicketComposer.PdfFileName(analysis, draft);
            lblSub.Text = (string.IsNullOrWhiteSpace(draft.Tenant) ? "" : draft.Tenant + "   ·   ") + analysis.MonthLabel + "   ·   audited " + J.FormatDateTime(analysis.AuditTime);
        }

        private void UpdateBanner()
        {
            string text = null; Color back = Color.Empty, fore = Color.Empty;
            if (draft == null) { lblBanner.Visible = false; return; }
            if (draft.IsSubmitted)
            {
                DateTime when;
                string at = DateTime.TryParse(draft.SubmittedAt, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out when) ? J.FormatDateTime(when.ToLocalTime()) : draft.SubmittedAt;
                text = "✓  Submitted " + at + " to " + draft.SubmittedTo + ". Edits after this need Submit ticket again.";
                back = Color.FromArgb(220, 252, 231); fore = Color.FromArgb(21, 128, 61);
            }
            else if (draft.Source == "Scheduled")
            {
                text = "Scheduled audit collected " + J.FormatDateTime(analysis.AuditTime) + ". Complete the manual checks, then press Submit ticket.";
                back = Color.FromArgb(254, 243, 199); fore = Color.FromArgb(146, 64, 14);
            }
            else
            {
                text = "Draft — complete the manual checks, then press Submit ticket.";
                back = Color.FromArgb(219, 234, 254); fore = Color.FromArgb(30, 64, 175);
            }
            if (report != null && report.Incomplete) text += "   (Collection was interrupted; results are partial.)";
            if (report != null && !report.Elevated) text += "   (Collected without administrator rights.)";
            lblBanner.Text = text; lblBanner.BackColor = back; lblBanner.ForeColor = fore; lblBanner.Visible = true;
        }

        private void UpdatePill()
        {
            if (analysis == null) { lblPill.Visible = false; return; }
            Severity s = ReportPdf.Overall(analysis, draft);
            lblPill.Text = ReportPdf.OverallLabel(s).ToUpperInvariant();
            lblPill.BackColor = StrongColor(s);
            lblPill.Visible = true;
            lblPill.Location = new Point(lblPill.Parent.ClientSize.Width - lblPill.Width - 22, 26);
        }

        private void UpdateReadiness()
        {
            if (analysis == null || draft == null) { lblReady.Text = ""; return; }
            var open = draft.Validate(analysis);
            var mail = settings.ValidateMail();
            if (mail.Count > 0)
            {
                lblReady.Text = "Email not set up";
                lblReady.ForeColor = Color.FromArgb(180, 83, 9);
                tips.SetToolTip(lblReady, "• " + string.Join("\n• ", mail.ToArray()));
            }
            else
            {
                lblReady.Text = draft.IsSubmitted ? "Submitted" : "✓ Ready to submit" + (open.Count > 0 ? " (" + J.Plural(open.Count, "item", "items") + " not filled in)" : "");
                lblReady.ForeColor = Color.FromArgb(21, 128, 61);
                tips.SetToolTip(lblReady, open.Count > 0 ? "Optional; the ticket can be sent as is:\n• " + string.Join("\n• ", open.ToArray()) : "");
            }
            UpdatePill();
        }

        private void UpdateEnabled()
        {
            bool loaded = analysis != null;
            btnRun.Enabled = !busy;
            btnOpen.Enabled = !busy;
            btnSettings.Enabled = !busy;
            btnUpdate.Enabled = !busy;
            btnPreview.Enabled = !busy && loaded;
            btnSubmit.Enabled = !busy && loaded;
            btnCancel.Enabled = busy && cts != null && !cts.IsCancellationRequested;
            chkDeep.Enabled = chkOnline.Enabled = !busy;
            progress.Visible = busy;
        }

        private void SetBusy(bool on, string text)
        {
            busy = on;
            lblProgress.Text = text;
            lblProgress.Location = new Point(on ? 226 : 18, 20);
            UseWaitCursor = false;
            UpdateEnabled();
        }

        // ------------------------------------------------------------ actions

        private async void RunAudit()
        {
            if (draft != null && !draft.IsSubmitted && analysis != null &&
                MessageBox.Show(this, "Collect fresh data for this server now? Manual check answers and notes for this month are kept.", "Run audit", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK)
                return;
            settings.DeepAudit = chkDeep.Checked;
            settings.OnlineUpdateScan = chkOnline.Checked;
            try { settings.Save(); } catch (Exception ex) { Log.Write("Settings save failed: " + ex.Message); }

            txtLog.Clear();
            checksDone = 0;
            progress.Value = 0;
            progress.Maximum = settings.DeepAudit ? 100 : 80;
            cts = new CancellationTokenSource();
            SetBusy(true, "Starting the collector… (typically 3–10 minutes)");
            tabs.SelectedTab = tabLog;
            var opts = new CollectorOptions { DeepAudit = chkDeep.Checked, OnlineUpdateScan = chkOnline.Checked, ExternalExposureCheck = settings.ExternalExposureCheck };
            string path = null; Exception error = null;
            try { path = await Task.Run(() => CollectorRunner.Run(opts, OnCollectorLine, cts.Token)); }
            catch (Exception ex) { error = ex; }
            bool cancelled = cts.IsCancellationRequested;
            cts = null;
            SetBusy(false, error == null ? "Audit collected." : "Audit failed.");
            if (error != null)
            {
                Log.Write("Collector failed: " + error);
                MessageBox.Show(this, error.Message, "Audit failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (cancelled && MessageBox.Show(this, "The audit was cancelled. Load the partial results collected so far?", "Run audit", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                return;
            LoadReport(path, "Manual");
            CollectorRunner.PruneRuns(settings.KeepRunsMonths, path);
            tabs.SelectedTab = tabFindings;
        }

        private static readonly Regex Collecting = new Regex(@"^Collecting (.+?) \(limit");
        private static readonly Regex Finished = new Regex(@"^\s+(\S.*?) : (\w+) \(");

        private void OnCollectorLine(string line)
        {
            if (IsDisposed) return;
            BeginInvoke(new Action(() =>
            {
                txtLog.AppendText(line + Environment.NewLine);
                Match m = Collecting.Match(line);
                if (m.Success) lblProgress.Text = "Checking " + m.Groups[1].Value + "…   (" + checksDone + " checks done)";
                if (Finished.IsMatch(line))
                {
                    checksDone++;
                    if (checksDone >= progress.Maximum) progress.Maximum = checksDone + 10;
                    progress.Value = checksDone;
                }
            }));
        }

        private void OpenReport()
        {
            using (var dlg = new OpenFileDialog { Title = "Open an audit report", Filter = "Audit collector JSON (WinFixAudit-*.json)|WinFixAudit-*.json|All JSON files|*.json", InitialDirectory = Directory.Exists(AppPaths.RunsDir) ? AppPaths.RunsDir : "" })
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                LoadReport(dlg.FileName, "Manual");
                tabs.SelectedTab = tabFindings;
            }
        }

        private void OpenSettings()
        {
            using (var f = new SettingsForm(settings))
            {
                if (f.ShowDialog(this) != DialogResult.OK) return;
                settings = AppSettings.Load();
                chkDeep.Checked = settings.DeepAudit;
                chkOnline.Checked = settings.OnlineUpdateScan;
                if (report != null)
                {
                    analysis = Workflow.Analyze(report, settings);
                    if (!draft.IsSubmitted) draft.ApplyAuto(analysis);
                    Populate();
                }
            }
        }

        private void PreviewPdf()
        {
            if (analysis == null) return;
            try
            {
                string dir = Path.Combine(Path.GetTempPath(), "PolarniteAuditPreview");
                Directory.CreateDirectory(dir);
                string path = Path.Combine(dir, TicketComposer.PdfFileName(analysis, draft));
                File.WriteAllBytes(path, ReportPdf.Render(analysis, draft, settings.CompanyName));
                try { Process.Start(path); }
                catch { MessageBox.Show(this, "The preview was saved to:\n" + path + "\n\nNo PDF viewer is registered on this server; copy the file to view it.", "Preview PDF", MessageBoxButtons.OK, MessageBoxIcon.Information); }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Could not build the PDF:\n\n" + ex.Message, "Preview PDF", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private async void Submit()
        {
            if (analysis == null || draft == null) return;
            SaveDraft();
            // Nothing the technician fills in is required; only missing email settings stop sending.
            var mail = settings.ValidateMail();
            if (mail.Count > 0)
            {
                MessageBox.Show(this, "The ticket can't be emailed until these are set (Settings, or the smtp2go fields in NinjaOne):\n\n• " + string.Join("\n• ", mail.ToArray()), "Email not set up", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            draft.FillDefaults(analysis);
            if (draft.IsSubmitted && MessageBox.Show(this, "This audit was already submitted to " + draft.SubmittedTo + ". Send it again?", "Submit ticket", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                return;
            string subject = TicketComposer.Subject(settings, analysis, draft);
            if (MessageBox.Show(this, "Send the audit ticket now?\n\nTo:  " + settings.ToAddress + "\nSubject:  " + subject + "\nAttachment:  " + TicketComposer.PdfFileName(analysis, draft),
                "Submit ticket", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK)
                return;

            SetBusy(true, "Building the PDF and sending the ticket…");
            AppSettings s = settings; AuditAnalysis a = analysis; DraftState d = draft;
            Exception error = null; string pdf = null;
            try { pdf = await Task.Run(() => Workflow.Submit(s, a, d, null)); }
            catch (Exception ex) { error = ex; }
            SetBusy(false, error == null ? "Ticket sent." : "Sending failed.");
            if (error != null)
            {
                Log.Write("Submit failed: " + error);
                string msg = error.Message;
                for (Exception inner = error.InnerException; inner != null; inner = inner.InnerException) msg += "\n" + inner.Message;
                MessageBox.Show(this, "The ticket was not sent:\n\n" + msg, "Submit ticket", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            lastAnswers = DraftStore.LoadLastAnswers();
            Populate();
            MessageBox.Show(this, "Ticket sent to " + settings.ToAddress + ".\n\nPDF saved at:\n" + pdf, "Submit ticket", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        // ------------------------------------------------------------ screenshots (test mode)

        public void SaveScreenshots(string dir)
        {
            Directory.CreateDirectory(dir);
            var pages = new[] { tabOverview, tabFindings, tabManual };
            foreach (TabPage p in pages)
            {
                tabs.SelectedTab = p;
                Application.DoEvents();
                using (var bmp = new Bitmap(Width, Height))
                {
                    DrawToBitmap(bmp, new Rectangle(0, 0, Width, Height));
                    bmp.Save(Path.Combine(dir, "ui-" + p.Text.Replace(" ", "-").ToLowerInvariant() + ".png"), System.Drawing.Imaging.ImageFormat.Png);
                }
            }
        }
    }
}
