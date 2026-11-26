using System;
using System.Drawing;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace PolarniteAudit
{
    internal sealed class SettingsForm : Form
    {
        private readonly AppSettings original;
        private TextBox txtNinjaHost, txtNinjaClient;
        private TextBox txtCompany, txtTo, txtFrom, txtFromName, txtHost, txtUser, txtPassword, txtSubject, txtTenant, txtAgents, txtTime;
        private NumericUpDown numPort, numDay;
        private CheckBox chkTls, chkClearPassword, chkDeep, chkOnline, chkExposure;
        private Label lblSchedule, lblPasswordState;
        private Button btnTest, btnSchedule, btnUnschedule, btnOk, btnCancel;

        public SettingsForm(AppSettings settings)
        {
            original = settings;
            Text = "Settings & schedule";
            Font = new Font("Segoe UI", 9F);
            AutoScaleMode = AutoScaleMode.Dpi;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(640, 690);
            BackColor = Color.White;
            Build();
            Fill(settings);
        }

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);
            MainForm.FitToScreen(this, false);   // the settings list scrolls; Save/Cancel stay visible at the bottom
        }

        private TableLayoutPanel grid;

        private void Row(string label, Control field, string hint)
        {
            var l = new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 7, 10, 3), ForeColor = MainForm.MutedText };
            field.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            field.Margin = new Padding(0, 3, 0, 3);
            grid.Controls.Add(l);
            grid.Controls.Add(field);
            if (!string.IsNullOrEmpty(hint)) new ToolTip().SetToolTip(field, hint);
        }

        private void Heading(string text)
        {
            var h = new Label { Text = text, AutoSize = true, Font = new Font("Segoe UI Semibold", 10.5F), Margin = new Padding(0, 14, 0, 4) };
            grid.Controls.Add(h);
            grid.SetColumnSpan(h, 2);
        }

        private void Build()
        {
            grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, Padding = new Padding(18, 6, 18, 6), AutoScroll = true };
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 170));
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

            Heading("NinjaOne");
            Row("NinjaOne host", txtNinjaHost = new TextBox(), "API host for your NinjaOne region, for example app.ninjarmm.com.");
            Row("Client app ID", txtNinjaClient = new TextBox(), "Client ID of the read-only Native app in NinjaOne (Administration > Apps > API). Technicians sign in with their own NinjaOne account; no secret is stored.");
            Heading("Ticket");
            Row("Send tickets to", txtTo = new TextBox(), "Helpdesk mailbox that turns emails into tickets.");
            Row("Company name", txtCompany = new TextBox(), "Shown on the PDF cover and footer.");
            Row("Subject template", txtSubject = new TextBox(), "Placeholders: {tenant} {server} {month} {status}");
            Row("Default tenant / client", txtTenant = new TextBox(), "Used when no Entra tenant is found (device join or Microsoft 365 sign-in) and the server has no domain. Can be changed per audit.");
            Row("Required agents", txtAgents = new TextBox(), "Comma-separated service names to require, e.g. Ninja, Huntress. A missing or stopped agent is a critical finding.");

            Heading("SMTP (sending)");
            Row("From address", txtFrom = new TextBox(), "Mailbox the ticket is sent from. It must be allowed to send through the SMTP server.");
            Row("From name", txtFromName = new TextBox(), null);
            Row("SMTP server", txtHost = new TextBox(), "e.g. smtp.office365.com, your relay, or smtp.sendgrid.net");
            var portRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
            numPort = new NumericUpDown { Minimum = 1, Maximum = 65535, Width = 80 };
            chkTls = new CheckBox { Text = "Use STARTTLS (required for 587)", AutoSize = true, Margin = new Padding(14, 4, 0, 0) };
            portRow.Controls.Add(numPort);
            portRow.Controls.Add(chkTls);
            Row("Port", portRow, "587 with STARTTLS is typical. Port 465 (implicit TLS) is not supported by Windows' built-in mail client.");
            Row("Username", txtUser = new TextBox(), "Leave blank for an IP-authorised relay (no login).");
            Row("Password", txtPassword = new TextBox { UseSystemPasswordChar = true }, "Encrypted with Windows DPAPI for this computer. Leave blank to keep the saved password.");
            var pwRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
            lblPasswordState = new Label { AutoSize = true, ForeColor = MainForm.MutedText, Margin = new Padding(0, 4, 10, 0) };
            chkClearPassword = new CheckBox { Text = "Clear saved password", AutoSize = true };
            pwRow.Controls.Add(lblPasswordState);
            pwRow.Controls.Add(chkClearPassword);
            Row("", pwRow, null);
            btnTest = new Button { Text = "Send test email", AutoSize = true, Anchor = AnchorStyles.Left };
            Row("", btnTest, "Sends a short test message to the ticket address using the values above.");

            Heading("Monthly schedule");
            var schedRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
            numDay = new NumericUpDown { Minimum = 1, Maximum = 28, Width = 60 };
            txtTime = new TextBox { Width = 60 };
            schedRow.Controls.Add(new Label { Text = "Day", AutoSize = true, Margin = new Padding(0, 6, 6, 0) });
            schedRow.Controls.Add(numDay);
            schedRow.Controls.Add(new Label { Text = "at", AutoSize = true, Margin = new Padding(10, 6, 6, 0) });
            schedRow.Controls.Add(txtTime);
            schedRow.Controls.Add(new Label { Text = "(24-hour, server time)", AutoSize = true, ForeColor = MainForm.MutedText, Margin = new Padding(8, 6, 0, 0) });
            Row("Run on", schedRow, null);
            chkDeep = new CheckBox { Text = "Deep audit (DC / server roles)", AutoSize = true };
            chkOnline = new CheckBox { Text = "Online Windows Update scan", AutoSize = true };
            Row("Options", chkDeep, null);
            Row("", chkOnline, null);
            chkExposure = new CheckBox { Text = "Internet exposure check (sends this site's public IP to ipify.org and Shodan InternetDB)", AutoSize = true, MaximumSize = new Size(420, 0) };
            Row("", chkExposure, "Looks up which ports Shodan has seen open on the site's public IP and fills in the exposure manual check. Off by default because it shares the client's IP with third parties.");
            var schedButtons = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
            btnSchedule = new Button { Text = "Create / update schedule", AutoSize = true };
            btnUnschedule = new Button { Text = "Remove schedule", AutoSize = true };
            schedButtons.Controls.Add(btnSchedule);
            schedButtons.Controls.Add(btnUnschedule);
            Row("", schedButtons, null);
            lblSchedule = new Label { AutoSize = true, ForeColor = MainForm.MutedText, MaximumSize = new Size(420, 0) };
            Row("Status", lblSchedule, null);
            var note = new Label
            {
                AutoSize = true, MaximumSize = new Size(420, 0), ForeColor = MainForm.MutedText,
                Text = "Scheduled runs collect the audit as SYSTEM and save it as a draft. Nothing is emailed until a technician completes the manual checks and presses Submit ticket. The app copies itself to C:\\ProgramData\\PolarniteServerAudit\\bin for the task."
            };
            Row("", note, null);

            var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, FlowDirection = FlowDirection.RightToLeft, Height = 50, Padding = new Padding(12, 8, 12, 8), BackColor = MainForm.Soft };
            btnCancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
            btnOk = new Button { Text = "Save", AutoSize = true };
            buttons.Controls.Add(btnCancel);
            buttons.Controls.Add(btnOk);
            Controls.Add(grid);
            Controls.Add(buttons);
            AcceptButton = btnOk;
            CancelButton = btnCancel;

            btnOk.Click += (s, e) => { if (SaveAll()) { DialogResult = DialogResult.OK; Close(); } };
            btnTest.Click += (s, e) => SendTest();
            btnSchedule.Click += (s, e) => CreateSchedule();
            btnUnschedule.Click += (s, e) => RemoveSchedule();
            Shown += (s, e) => RefreshSchedule();
        }

        private void Fill(AppSettings s)
        {
            txtTo.Text = s.ToAddress;
            txtCompany.Text = s.CompanyName;
            txtSubject.Text = s.SubjectTemplate;
            txtTenant.Text = s.DefaultTenant;
            txtNinjaHost.Text = s.NinjaHost;
            txtNinjaClient.Text = s.NinjaClientId;
            txtAgents.Text = s.ExpectedAgents;
            txtFrom.Text = s.FromAddress;
            txtFromName.Text = s.FromName;
            txtHost.Text = s.SmtpHost;
            numPort.Value = Math.Max(1, Math.Min(65535, s.SmtpPort));
            chkTls.Checked = s.SmtpStartTls;
            txtUser.Text = s.SmtpUser;
            lblPasswordState.Text = string.IsNullOrEmpty(s.SmtpPasswordProtected) ? "No password saved." : "A password is saved (encrypted).";
            numDay.Value = Math.Max(1, Math.Min(28, s.ScheduleDay));
            txtTime.Text = s.ScheduleTime;
            chkDeep.Checked = s.DeepAudit;
            chkOnline.Checked = s.OnlineUpdateScan;
            chkExposure.Checked = s.ExternalExposureCheck;
        }

        /// <summary>Copies the form into a settings object (starting from the saved one so unknown fields survive).</summary>
        private AppSettings Collect()
        {
            AppSettings s = AppSettings.Load();
            s.ToAddress = txtTo.Text.Trim();
            s.CompanyName = txtCompany.Text.Trim();
            s.SubjectTemplate = txtSubject.Text.Trim();
            s.DefaultTenant = txtTenant.Text.Trim();
            s.NinjaHost = txtNinjaHost.Text.Trim().Length > 0 ? txtNinjaHost.Text.Trim() : Ninja.DefaultHost;
            s.NinjaClientId = txtNinjaClient.Text.Trim().Length > 0 ? txtNinjaClient.Text.Trim() : Ninja.DefaultClientId;
            s.ExpectedAgents = txtAgents.Text.Trim();
            s.FromAddress = txtFrom.Text.Trim();
            s.FromName = txtFromName.Text.Trim();
            s.SmtpHost = txtHost.Text.Trim();
            s.SmtpPort = (int)numPort.Value;
            s.SmtpStartTls = chkTls.Checked;
            s.SmtpUser = txtUser.Text.Trim();
            if (chkClearPassword.Checked) s.SmtpPassword = "";
            else if (txtPassword.Text.Length > 0) s.SmtpPassword = txtPassword.Text;
            s.ScheduleDay = (int)numDay.Value;
            s.ScheduleTime = txtTime.Text.Trim();
            s.DeepAudit = chkDeep.Checked;
            s.OnlineUpdateScan = chkOnline.Checked;
            s.ExternalExposureCheck = chkExposure.Checked;
            s.LastTechnician = original.LastTechnician;
            return s;
        }

        private bool SaveAll()
        {
            AppSettings s = Collect();
            if (!AppSettings.IsEmail(s.ToAddress))
            {
                MessageBox.Show(this, "Enter a valid ticket email address.", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }
            try { s.Save(); return true; }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Settings could not be saved:\n\n" + ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
        }

        private async void SendTest()
        {
            AppSettings s = Collect();
            var problems = s.ValidateMail();
            if (problems.Count > 0)
            {
                MessageBox.Show(this, "\u2022 " + string.Join("\n\u2022 ", problems.ToArray()), "Send test email", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            btnTest.Enabled = false;
            btnTest.Text = "Sending\u2026";
            Exception error = null;
            string subject = AppInfo.Name + " test from " + Environment.MachineName;
            string body = "This is a test message from " + AppInfo.Name + " on " + Environment.MachineName + ". If it arrived, SMTP settings are working.";
            try { await Task.Run(() => Mailer.Send(s, subject, "<p>" + J.HtmlEncode(body) + "</p>", body, null, null)); }
            catch (Exception ex) { error = ex; }
            btnTest.Enabled = true;
            btnTest.Text = "Send test email";
            if (error == null)
            {
                try { s.Save(); } catch { }
                MessageBox.Show(this, "Test email sent to " + s.ToAddress + ". The settings have been saved.", "Send test email", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                string msg = error.Message;
                for (Exception inner = error.InnerException; inner != null; inner = inner.InnerException) msg += "\n" + inner.Message;
                Log.Write("Test email failed: " + error);
                MessageBox.Show(this, "The test email failed:\n\n" + msg, "Send test email", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void RefreshSchedule()
        {
            try { lblSchedule.Text = Scheduler.Status(); }
            catch (Exception ex) { lblSchedule.Text = "Unknown (" + ex.Message + ")"; }
        }

        private void CreateSchedule()
        {
            if (!SaveAll()) return;
            try
            {
                string result = Scheduler.Install(AppSettings.Load());
                RefreshSchedule();
                MessageBox.Show(this, "Monthly audit scheduled. " + result + "\n\nEach run saves a draft; open this app to complete the manual checks and submit the ticket.", Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "The schedule could not be created:\n\n" + ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void RemoveSchedule()
        {
            try { Scheduler.Remove(); }
            catch (Exception ex) { MessageBox.Show(this, ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
            RefreshSchedule();
        }
    }
}
