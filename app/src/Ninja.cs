using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PolarniteAudit
{
    /// <summary>
    /// NinjaOne integration. A technician signs in through the browser (OAuth authorization code + PKCE,
    /// a "Native" client app with the read-only Monitoring scope). The access token lives only in this
    /// process: nothing that could read other clients' NinjaOne data is stored on the server.
    /// </summary>
    internal static class Ninja
    {
        public const string DefaultHost = "app.ninjarmm.com";
        public const string DefaultClientId = "-KXIEt2vBjMPOvAYivvEIWdbBQM";   // "Polarnite Server Audit Tool" (Native, Monitoring scope); not a secret

        private static string token, tokenHost;
        private static DateTime tokenExpiresUtc;

        public static bool SignedIn { get { return token != null && DateTime.UtcNow < tokenExpiresUtc.AddMinutes(-1); } }

        public static void SignOut() { token = null; tokenHost = null; }

        private static string Base64Url(byte[] b) { return Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_'); }

        private static string RandomToken(int bytes)
        {
            var b = new byte[bytes];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(b);
            return Base64Url(b);
        }

        /// <summary>Opens the NinjaOne sign-in page in the browser and waits (up to 5 minutes) for the redirect back to this app.</summary>
        public static void SignIn(string host, string clientId, CancellationToken ct, Action<string> status)
        {
            host = string.IsNullOrWhiteSpace(host) ? DefaultHost : host.Trim();
            clientId = string.IsNullOrWhiteSpace(clientId) ? DefaultClientId : clientId.Trim();
            string verifier = RandomToken(48), state = RandomToken(16), challenge;
            using (var sha = SHA256.Create()) challenge = Base64Url(sha.ComputeHash(Encoding.ASCII.GetBytes(verifier)));

            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                int port = ((IPEndPoint)listener.LocalEndpoint).Port;
                string redirect = "http://127.0.0.1:" + port + "/";
                string url = "https://" + host + "/ws/oauth/authorize?response_type=code&client_id=" + Uri.EscapeDataString(clientId) +
                             "&redirect_uri=" + Uri.EscapeDataString(redirect) + "&scope=monitoring&state=" + state +
                             "&code_challenge=" + challenge + "&code_challenge_method=S256";
                try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
                catch (Exception ex) { throw new InvalidOperationException("Could not open a browser for the NinjaOne sign-in (" + ex.Message + "). Open this address manually:\n" + url); }
                if (status != null) status("Waiting for the NinjaOne sign-in in your browser…");

                string code = null;
                DateTime deadline = DateTime.UtcNow.AddMinutes(5);
                while (code == null)
                {
                    Task<TcpClient> accept = listener.AcceptTcpClientAsync();
                    while (!accept.Wait(500))
                    {
                        ct.ThrowIfCancellationRequested();
                        if (DateTime.UtcNow > deadline) throw new TimeoutException("The NinjaOne sign-in was not completed within 5 minutes.");
                    }
                    using (TcpClient client = accept.Result)
                    using (NetworkStream stream = client.GetStream())
                    {
                        stream.ReadTimeout = 5000;
                        var reader = new StreamReader(stream, Encoding.ASCII);
                        string requestLine = reader.ReadLine() ?? "";
                        string target = requestLine.Split(' ').Length > 1 ? requestLine.Split(' ')[1] : "";
                        var query = ParseQuery(target.Contains("?") ? target.Substring(target.IndexOf('?') + 1) : "");
                        string message;
                        if (query.ContainsKey("error")) message = "NinjaOne sign-in failed: " + (query.ContainsKey("error_description") ? query["error_description"] : query["error"]);
                        else if (query.ContainsKey("code") && query.ContainsKey("state") && query["state"] == state) { code = query["code"]; message = "Signed in to NinjaOne. You can close this tab and return to " + AppInfo.Name + "."; }
                        else message = null;   // favicon or unrelated request
                        string body = "<html><body style=\"font-family:Segoe UI,Arial;padding:40px\"><h2>" + WebUtility.HtmlEncode(message ?? "Waiting for NinjaOne…") + "</h2></body></html>";
                        byte[] bytes = Encoding.UTF8.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nContent-Length: " + Encoding.UTF8.GetByteCount(body) + "\r\n\r\n" + body);
                        stream.Write(bytes, 0, bytes.Length);
                        if (message != null && code == null) throw new InvalidOperationException(message);
                    }
                }

                if (status != null) status("Signing in to NinjaOne…");
                object tok = Post("https://" + host + "/ws/oauth/token", "grant_type=authorization_code&client_id=" + Uri.EscapeDataString(clientId) +
                    "&code=" + Uri.EscapeDataString(code) + "&redirect_uri=" + Uri.EscapeDataString(redirect) + "&code_verifier=" + verifier);
                token = J.Str(tok, "access_token");
                if (token.Length == 0) throw new InvalidOperationException("NinjaOne did not return an access token.");
                tokenHost = host;
                tokenExpiresUtc = DateTime.UtcNow.AddSeconds(J.Num(tok, "expires_in") ?? 3600);
                Log.Write("Signed in to NinjaOne (" + host + ").");
            }
            finally { listener.Stop(); }
        }

        private static Dictionary<string, string> ParseQuery(string q)
        {
            var d = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (string part in q.Split('&'))
            {
                if (part.Length == 0) continue;
                int i = part.IndexOf('=');
                string k = Uri.UnescapeDataString((i < 0 ? part : part.Substring(0, i)).Replace('+', ' '));
                d[k] = i < 0 ? "" : Uri.UnescapeDataString(part.Substring(i + 1).Replace('+', ' '));
            }
            return d;
        }

        private static WebClient Client()
        {
            ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072;
            var wc = new WebClient { Encoding = Encoding.UTF8 };
            wc.Headers[HttpRequestHeader.UserAgent] = "PolarniteServerAuditTool";
            wc.Headers[HttpRequestHeader.Accept] = "application/json";
            return wc;
        }

        private static object Post(string url, string form)
        {
            using (WebClient wc = Client())
            {
                wc.Headers[HttpRequestHeader.ContentType] = "application/x-www-form-urlencoded";
                try { return J.Parse(wc.UploadString(url, form)); }
                catch (WebException ex) { throw new InvalidOperationException("NinjaOne sign-in failed: " + Describe(ex)); }
            }
        }

        private static object Get(string path)
        {
            if (!SignedIn) throw new InvalidOperationException("Not signed in to NinjaOne.");
            using (WebClient wc = Client())
            {
                wc.Headers[HttpRequestHeader.Authorization] = "Bearer " + token;
                return J.Parse(wc.DownloadString("https://" + tokenHost + path));
            }
        }

        private static string Describe(WebException ex)
        {
            var resp = ex.Response as HttpWebResponse;
            if (resp == null) return ex.Message;
            string body = "";
            try { using (var r = new StreamReader(resp.GetResponseStream())) body = r.ReadToEnd(); } catch { }
            return (int)resp.StatusCode + " " + resp.StatusDescription + (body.Length > 0 ? ": " + J.Shorten(body, 200) : "");
        }

        // ------------------------------------------------------------ device data

        private static string Name(string s) { s = (s ?? "").Trim(); int dot = s.IndexOf('.'); return (dot > 0 ? s.Substring(0, dot) : s).ToUpperInvariant(); }

        /// <summary>
        /// Finds this server in NinjaOne (by name, confirmed by serial number when several match) and reads
        /// its details, organization, open alerts, OS patches and antivirus status/threats.
        /// The result is stored next to the audit report as &lt;report&gt;.ninja.json.
        /// </summary>
        public static Dictionary<string, object> Fetch(string computerName, string serialNumber, Action<string> status)
        {
            var result = new Dictionary<string, object>();
            var errors = new List<object>();
            result["Host"] = tokenHost;
            result["FetchedUtc"] = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
            result["Errors"] = errors;

            if (status != null) status("Finding " + computerName + " in NinjaOne…");
            object search = Get("/v2/devices/search?q=" + Uri.EscapeDataString(computerName) + "&limit=25");
            var candidates = J.List(J.Get(search, "devices"))
                .Where(d => new[] { J.Str(d, "systemName"), J.Str(d, "displayName"), J.Str(d, "dnsName"), J.Str(d, "netbiosName") }.Any(n => n.Length > 0 && Name(n) == Name(computerName)))
                .Where(d => J.Str(d, "approvalStatus") != "DECOMMISSIONED")
                .ToList();
            result["Candidates"] = candidates.Count;
            if (candidates.Count == 0) { result["Matched"] = false; result["MatchNote"] = "No NinjaOne device is named " + computerName + "."; return result; }

            object device = null; string how = "name";
            var details = new List<object>();
            foreach (object c in candidates.Take(5))
            {
                try { details.Add(Get("/v2/device/" + J.Str(c, "id"))); } catch (Exception ex) { errors.Add("device " + J.Str(c, "id") + ": " + ex.Message); }
            }
            string serial = (serialNumber ?? "").Trim();
            if (serial.Length > 0)
            {
                device = details.FirstOrDefault(d => string.Equals(J.Str(J.Get(d, "system"), "serialNumber").Trim(), serial, StringComparison.OrdinalIgnoreCase)
                                                  || string.Equals(J.Str(J.Get(d, "system"), "biosSerialNumber").Trim(), serial, StringComparison.OrdinalIgnoreCase));
                if (device != null) how = "name and serial number";
            }
            if (device == null && details.Count == 1) device = details[0];
            if (device == null && details.Count > 1)
            {
                // Several devices share the name and none matches the serial: take the one seen most recently.
                device = details.OrderByDescending(d => J.Num(d, "lastContact") ?? 0).First();
                how = "name (most recently seen of " + details.Count + ")";
            }
            if (device == null) { result["Matched"] = false; result["MatchNote"] = "Device details could not be read."; return result; }
            result["Matched"] = true;
            result["MatchedBy"] = how;
            result["Device"] = device;
            string id = J.Str(device, "id");

            Action<string, string, Func<object>> step = (key, label, fn) =>
            {
                if (status != null) status("Reading " + label + " from NinjaOne…");
                try { result[key] = fn(); }
                catch (Exception ex) { errors.Add(label + ": " + (ex is WebException ? Describe((WebException)ex) : ex.Message)); }
            };
            string orgId = J.Str(device, "organizationId");
            if (orgId.Length > 0) step("Organization", "organization", () => Get("/v2/organization/" + orgId));
            step("Alerts", "alerts", () => Get("/v2/device/" + id + "/alerts"));
            step("OsPatches", "OS patches", () => Get("/v2/device/" + id + "/os-patches"));
            step("AntivirusStatus", "antivirus status", () => J.Get(Get("/v2/queries/antivirus-status?df=" + Uri.EscapeDataString("id=" + id) + "&pageSize=20"), "results"));
            step("AntivirusThreats", "antivirus threats", () => J.Get(Get("/v2/queries/antivirus-threats?df=" + Uri.EscapeDataString("id=" + id) + "&pageSize=100"), "results"));
            step("DashboardUrl", "dashboard link", () => J.Get(Get("/v2/device/" + id + "/dashboard-url"), "url"));
            return result;
        }

        /// <summary>Where NinjaOne data for an audit report is kept.</summary>
        public static string SidecarPath(string reportPath) { return Path.ChangeExtension(reportPath, ".ninja.json"); }

        /// <summary>NinjaOne times are Unix seconds (sometimes milliseconds).</summary>
        public static DateTime? Time(object v)
        {
            double? n = J.Num(v);
            if (!n.HasValue || n.Value <= 0) return null;
            double s = n.Value > 1e11 ? n.Value / 1000 : n.Value;
            return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(s).ToLocalTime();
        }
    }
}
