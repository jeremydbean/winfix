using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace WinFixAudit
{
    /// <summary>
    /// Helpers for reading the loosely-typed collector JSON. The collector runs on
    /// PowerShell 4/5.1 (and could run on 7), so values arrive in several shapes:
    /// dates as "\/Date(ms)\/", ISO strings or {value,DateTime} objects; enums as
    /// numbers or names; single items as objects instead of one-element arrays.
    /// </summary>
    internal static class J
    {
        private static JavaScriptSerializer NewSerializer()
        {
            var s = new JavaScriptSerializer();
            s.MaxJsonLength = int.MaxValue;
            s.RecursionLimit = 512;
            return s;
        }

        public static object Parse(string text)
        {
            return NewSerializer().DeserializeObject(text);
        }

        public static string Serialize(object value)
        {
            return NewSerializer().Serialize(value);
        }

        public static IDictionary<string, object> Dict(object o)
        {
            return o as IDictionary<string, object>;
        }

        public static object Get(object o, params string[] path)
        {
            object cur = o;
            foreach (string key in path)
            {
                var d = cur as IDictionary<string, object>;
                if (d == null) return null;
                object next;
                if (!d.TryGetValue(key, out next))
                {
                    next = null;
                    foreach (var kv in d)
                    {
                        if (string.Equals(kv.Key, key, StringComparison.OrdinalIgnoreCase)) { next = kv.Value; break; }
                    }
                    if (next == null) return null;
                }
                cur = next;
            }
            return cur;
        }

        public static List<object> List(object o)
        {
            var result = new List<object>();
            if (o == null) return result;
            if (o is string || o is IDictionary<string, object>) { result.Add(o); return result; }
            var e = o as IEnumerable;
            if (e != null)
            {
                foreach (object x in e) if (x != null) result.Add(x);
                return result;
            }
            result.Add(o);
            return result;
        }

        public static string Str(object o)
        {
            if (o == null) return "";
            if (o is string)
            {
                string s = (string)o;
                if (s.StartsWith("/Date(", StringComparison.Ordinal))
                {
                    DateTime? d = Date(s);
                    return d.HasValue ? d.Value.ToString("yyyy-MM-dd HH:mm") : s;
                }
                return s;
            }
            if (o is DateTime) return ((DateTime)o).ToLocalTime().ToString("yyyy-MM-dd HH:mm");
            if (o is bool) return ((bool)o) ? "True" : "False";
            if (o is IFormattable) return ((IFormattable)o).ToString(null, CultureInfo.InvariantCulture);
            var d2 = o as IDictionary<string, object>;
            if (d2 != null)
            {
                object v = Get(d2, "Value");
                if (v != null) return Str(v);
                v = Get(d2, "DateTime");
                if (v != null) return Str(v);
                return "";
            }
            var e = o as IEnumerable;
            if (e != null)
            {
                var parts = new List<string>();
                foreach (object x in e) { string p = Str(x); if (p.Length > 0) parts.Add(p); }
                return string.Join(", ", parts.ToArray());
            }
            return o.ToString();
        }

        public static string Str(object o, params string[] path) { return Str(Get(o, path)); }

        public static double? Num(object o)
        {
            if (o == null) return null;
            if (o is bool) return ((bool)o) ? 1 : 0;
            if (o is int) return (int)o;
            if (o is long) return (long)o;
            if (o is decimal) return (double)(decimal)o;
            if (o is double) return (double)o;
            if (o is float) return (float)o;
            var d = o as IDictionary<string, object>;
            if (d != null) { object v = Get(d, "value"); return v == null ? null : Num(v); }
            double r;
            if (double.TryParse(Str(o), NumberStyles.Float, CultureInfo.InvariantCulture, out r)) return r;
            return null;
        }

        public static double? Num(object o, params string[] path) { return Num(Get(o, path)); }

        /// <summary>True/false from bools, 0/1, "True"/"On"/"Yes"; null when unknown.</summary>
        public static bool? Bool(object o)
        {
            if (o == null) return null;
            if (o is bool) return (bool)o;
            double? n = (o is string) ? null : Num(o);
            if (n.HasValue) return n.Value != 0;
            string s = Str(o).Trim().ToLowerInvariant();
            if (s == "true" || s == "on" || s == "yes" || s == "1" || s == "enabled") return true;
            if (s == "false" || s == "off" || s == "no" || s == "0" || s == "disabled") return false;
            return null;
        }

        public static bool? Bool(object o, params string[] path) { return Bool(Get(o, path)); }

        private static readonly Regex MsDate = new Regex(@"^/Date\((-?\d+)([+-]\d{4})?\)/$");

        /// <summary>Parses every date shape the collector emits; returns local time, or null for unset dates.</summary>
        public static DateTime? Date(object o)
        {
            if (o == null) return null;
            DateTime result;
            if (o is DateTime) result = ((DateTime)o).Kind == DateTimeKind.Unspecified ? (DateTime)o : ((DateTime)o).ToLocalTime();
            else
            {
                var d = o as IDictionary<string, object>;
                if (d != null)
                {
                    object v = Get(d, "value");
                    return v == null ? null : Date(v);
                }
                string s = Str(o).Trim();
                if (s.Length == 0) return null;
                Match m = MsDate.Match(s);
                if (m.Success)
                {
                    long ms = long.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture);
                    result = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddMilliseconds(ms).ToLocalTime();
                }
                else
                {
                    DateTimeOffset dto;
                    if (DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out dto)) result = dto.LocalDateTime;
                    else return null;
                }
            }
            // Task Scheduler reports 1999-11-30 for "never"; CIM uses 1601 for unset.
            if (result.Year < 2000) return null;
            return result;
        }

        public static DateTime? Date(object o, params string[] path) { return Date(Get(o, path)); }

        public static string Shorten(string s, int max)
        {
            if (s == null) return "";
            s = Regex.Replace(s, @"\s+", " ").Trim();
            if (s.Length <= max) return s;
            return s.Substring(0, Math.Max(0, max - 1)).TrimEnd() + "…";
        }

        public static string FormatDate(DateTime? d)
        {
            return d.HasValue ? d.Value.ToString("d MMM yyyy", CultureInfo.InvariantCulture) : "Unknown";
        }

        public static string FormatDateTime(DateTime? d)
        {
            return d.HasValue ? d.Value.ToString("d MMM yyyy HH:mm", CultureInfo.InvariantCulture) : "Unknown";
        }

        public static string Plural(int n, string one, string many)
        {
            return n.ToString(CultureInfo.InvariantCulture) + " " + (n == 1 ? one : many);
        }

        public static string HtmlEncode(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            var sb = new StringBuilder(s.Length + 16);
            foreach (char c in s)
            {
                switch (c)
                {
                    case '&': sb.Append("&amp;"); break;
                    case '<': sb.Append("&lt;"); break;
                    case '>': sb.Append("&gt;"); break;
                    case '"': sb.Append("&quot;"); break;
                    case '\'': sb.Append("&#39;"); break;
                    case '\n': sb.Append("<br>"); break;
                    case '\r': break;
                    default: sb.Append(c); break;
                }
            }
            return sb.ToString();
        }
    }
}
