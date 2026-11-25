using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Threading;
using System.Windows.Forms;

namespace PolarniteAudit
{
    /// <summary>What dist/latest.json on GitHub says about the newest published build.</summary>
    internal sealed class UpdateInfo
    {
        public DateTime BuiltUtc;
        public string Collector = "", Sha256 = "", File = AppInfo.ExeName;
        public long Size;
        public string BuiltText { get { return BuiltUtc.ToLocalTime().ToString("d MMM yyyy HH:mm", CultureInfo.InvariantCulture); } }
    }

    /// <summary>
    /// Self-update from the repository: reads app/dist/latest.json, downloads the exe it describes,
    /// checks its size and SHA-256 against the manifest, swaps it in place of the running exe and restarts.
    /// Only runs when a technician asks for it; scheduled runs never update themselves.
    /// </summary>
    internal static class Updater
    {
        private const string DefaultBase = "https://raw.githubusercontent.com/jeremydbean/winfix/main/app/dist/";

        // POLARNITE_UPDATE_URL points the updater somewhere else (a test folder or http URL).
        private static string Base
        {
            get
            {
                string o = Environment.GetEnvironmentVariable("POLARNITE_UPDATE_URL");
                return string.IsNullOrEmpty(o) ? DefaultBase : o.TrimEnd('/', '\\') + "/";
            }
        }

        public static DateTime CurrentBuiltUtc
        {
            get
            {
                DateTime d;
                return DateTime.TryParse(BuildInfo.BuiltUtc, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out d) ? d : DateTime.MinValue;
            }
        }

        public static string CurrentBuiltText { get { return CurrentBuiltUtc == DateTime.MinValue ? "unknown" : CurrentBuiltUtc.ToLocalTime().ToString("d MMM yyyy HH:mm", CultureInfo.InvariantCulture); } }

        private static WebClient Client()
        {
            ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072; // TLS 1.2 on .NET 4.5 / Server 2012 R2
            var wc = new WebClient();
            wc.Headers[HttpRequestHeader.UserAgent] = "PolarniteServerAuditTool-Updater";
            wc.Headers[HttpRequestHeader.CacheControl] = "no-cache";
            return wc;
        }

        private static byte[] Fetch(string name)
        {
            string url = Base + name;
            if (!url.StartsWith("http", StringComparison.OrdinalIgnoreCase)) return System.IO.File.ReadAllBytes(new Uri(url).LocalPath);
            using (WebClient wc = Client()) return wc.DownloadData(url + "?t=" + DateTime.UtcNow.Ticks.ToString(CultureInfo.InvariantCulture));
        }

        /// <summary>Reads the published manifest. Throws on network or format errors.</summary>
        public static UpdateInfo Check()
        {
            object o = J.Parse(System.Text.Encoding.UTF8.GetString(Fetch("latest.json")).TrimStart('﻿'));
            var u = new UpdateInfo
            {
                Collector = J.Str(o, "Collector"), Sha256 = J.Str(o, "Sha256").ToUpperInvariant(),
                File = J.Str(o, "File").Length > 0 ? J.Str(o, "File") : AppInfo.ExeName, Size = (long)(J.Num(o, "Size") ?? 0)
            };
            DateTime built;
            if (!DateTime.TryParse(J.Str(o, "BuiltUtc"), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out built))
                throw new InvalidDataException("latest.json has no BuiltUtc date.");
            u.BuiltUtc = built;
            if (u.Sha256.Length != 64 || u.Size <= 0 || u.File.IndexOfAny(new[] { '/', '\\', ':' }) >= 0) throw new InvalidDataException("latest.json is incomplete.");
            return u;
        }

        public static bool IsNewer(UpdateInfo u)
        {
            if (u == null || u.BuiltUtc <= CurrentBuiltUtc.AddMinutes(1)) return false;
            return !string.Equals(u.Sha256, Sha256(Application.ExecutablePath), StringComparison.OrdinalIgnoreCase);
        }

        public static string Sha256(string path)
        {
            using (var sha = SHA256.Create())
            using (FileStream fs = System.IO.File.OpenRead(path))
                return BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "");
        }

        /// <summary>Downloads the new exe to a temp file and verifies it against the manifest.</summary>
        public static string Download(UpdateInfo u)
        {
            byte[] data = Fetch(u.File);
            if (data.Length != u.Size || data.Length < 2 || data[0] != 'M' || data[1] != 'Z')
                throw new InvalidDataException("The downloaded file is not the expected program (" + data.Length + " bytes). GitHub may still be updating its cache; try again in a few minutes.");
            string hash;
            using (var sha = SHA256.Create()) hash = BitConverter.ToString(sha.ComputeHash(data)).Replace("-", "");
            if (!string.Equals(hash, u.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("The download does not match the published SHA-256. GitHub may still be updating its cache; try again in a few minutes.");
            string path = Path.Combine(Path.GetTempPath(), "PolarniteServerAuditTool-" + u.BuiltUtc.ToString("yyyyMMddHHmm", CultureInfo.InvariantCulture) + ".exe");
            System.IO.File.WriteAllBytes(path, data);
            return path;
        }

        /// <summary>
        /// Puts the new exe where the running one is (renaming the running file to .old, which Windows allows)
        /// and starts it. If this folder is read-only, starts the downloaded copy instead.
        /// Returns the path that was started.
        /// </summary>
        public static string InstallAndStart(string downloaded, bool start)
        {
            string self = Application.ExecutablePath;
            string target = self;
            try
            {
                string old = self + ".old";
                if (System.IO.File.Exists(old)) System.IO.File.Delete(old);
                System.IO.File.Move(self, old);
                try { System.IO.File.Copy(downloaded, self); }
                catch { System.IO.File.Move(old, self); throw; }
            }
            catch (Exception ex)
            {
                Log.Write("Update: could not replace " + self + " (" + ex.Message + "); starting the downloaded copy instead.");
                target = downloaded;
            }
            if (!start) return target;
            Log.Write("Update: starting " + target);
            Process.Start(new ProcessStartInfo(target, "--after-update") { UseShellExecute = true, WorkingDirectory = Path.GetDirectoryName(target) });
            return target;
        }

        /// <summary>--update: for RMM scripts. Replaces this exe (and the scheduled task's copy) without opening the app.</summary>
        public static int UpdateFromCommandLine()
        {
            try
            {
                UpdateInfo u = Check();
                if (!IsNewer(u)) { Log.Write("Update: already current (build " + CurrentBuiltText + ")."); Console.WriteLine("Already current: build " + CurrentBuiltText); return 2; }
                string file = Download(u);
                string target = InstallAndStart(file, false);
                if (!string.Equals(target, Application.ExecutablePath, StringComparison.OrdinalIgnoreCase)) throw new IOException("Could not replace " + Application.ExecutablePath + "; the new build is at " + target + ".");
                string installed = AppPaths.InstalledExe;
                if (System.IO.File.Exists(installed) && !string.Equals(Path.GetFullPath(installed), Path.GetFullPath(target), StringComparison.OrdinalIgnoreCase))
                    System.IO.File.Copy(file, installed, true);
                Log.Write("Update: installed build " + u.BuiltText + " to " + target + ".");
                Console.WriteLine("Updated to build " + u.BuiltText);
                return 0;
            }
            catch (Exception ex)
            {
                Log.Write("Update failed: " + ex.Message);
                Console.WriteLine("Update failed: " + ex.Message);
                return 1;
            }
        }

        /// <summary>Called by the new exe: removes the previous version once it has exited.</summary>
        public static void CleanupOld()
        {
            string old = Application.ExecutablePath + ".old";
            for (int i = 0; i < 10 && System.IO.File.Exists(old); i++)
            {
                try { System.IO.File.Delete(old); }
                catch { Thread.Sleep(500); }
            }
        }

        /// <summary>Keeps the copy used by the monthly scheduled task in step with the exe a technician runs.</summary>
        public static void RefreshScheduledCopy()
        {
            try
            {
                string self = Application.ExecutablePath, installed = AppPaths.InstalledExe;
                if (!System.IO.File.Exists(installed) || string.Equals(Path.GetFullPath(self), Path.GetFullPath(installed), StringComparison.OrdinalIgnoreCase)) return;
                if (string.Equals(Sha256(self), Sha256(installed), StringComparison.OrdinalIgnoreCase)) return;
                System.IO.File.Copy(self, installed, true);
                Log.Write("Updated the scheduled task's copy at " + installed + " to build " + CurrentBuiltText + ".");
            }
            catch (Exception ex) { Log.Write("Could not update the scheduled task's copy: " + ex.Message); }
        }
    }
}
