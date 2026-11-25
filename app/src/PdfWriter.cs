using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace PolarniteAudit
{
    internal struct Rgb
    {
        public readonly double R, G, B;
        public Rgb(int hex) { R = ((hex >> 16) & 0xFF) / 255.0; G = ((hex >> 8) & 0xFF) / 255.0; B = (hex & 0xFF) / 255.0; }
        public string Fill { get { return PdfDoc.N(R) + " " + PdfDoc.N(G) + " " + PdfDoc.N(B) + " rg"; } }
        public string Stroke { get { return PdfDoc.N(R) + " " + PdfDoc.N(G) + " " + PdfDoc.N(B) + " RG"; } }
    }

    internal enum PdfFont { Regular = 0, Bold = 1, Italic = 2 }

    /// <summary>
    /// Minimal dependency-free PDF writer: US Letter pages, the built-in Helvetica
    /// family (WinAnsi encoding), filled/stroked shapes and Flate-compressed
    /// content. Coordinates are points from the TOP-left corner.
    /// </summary>
    internal sealed class PdfDoc
    {
        public const double Width = 612, Height = 792;
        private readonly List<StringBuilder> pages = new List<StringBuilder>();
        private StringBuilder cur;
        public string Title = "", Author = "", Subject = "";

        public int PageCount { get { return pages.Count; } }
        public int PageIndex { get; private set; }

        public void NewPage()
        {
            cur = new StringBuilder();
            pages.Add(cur);
            PageIndex = pages.Count - 1;
        }

        public void SelectPage(int index) { cur = pages[index]; PageIndex = index; }

        internal static string N(double v)
        {
            return Math.Round(v, 3).ToString("0.###", CultureInfo.InvariantCulture);
        }

        private static double Y(double top) { return Height - top; }

        public void FillRect(double x, double y, double w, double h, Rgb c)
        {
            cur.Append(c.Fill).Append(' ').Append(N(x)).Append(' ').Append(N(Y(y + h))).Append(' ').Append(N(w)).Append(' ').Append(N(h)).Append(" re f\n");
        }

        public void StrokeRect(double x, double y, double w, double h, Rgb c, double lineWidth)
        {
            cur.Append(c.Stroke).Append(' ').Append(N(lineWidth)).Append(" w ").Append(N(x)).Append(' ').Append(N(Y(y + h))).Append(' ').Append(N(w)).Append(' ').Append(N(h)).Append(" re S\n");
        }

        public void Line(double x1, double y1, double x2, double y2, Rgb c, double lineWidth)
        {
            cur.Append(c.Stroke).Append(' ').Append(N(lineWidth)).Append(" w ").Append(N(x1)).Append(' ').Append(N(Y(y1))).Append(" m ")
               .Append(N(x2)).Append(' ').Append(N(Y(y2))).Append(" l S\n");
        }

        private void RoundPath(double x, double y, double w, double h, double r)
        {
            r = Math.Max(0, Math.Min(r, Math.Min(w, h) / 2));
            const double k = 0.5523;
            double x0 = x, x1 = x + w, yt = Y(y), yb = Y(y + h);
            cur.Append(N(x0 + r)).Append(' ').Append(N(yt)).Append(" m ");
            cur.Append(N(x1 - r)).Append(' ').Append(N(yt)).Append(" l ");
            cur.Append(N(x1 - r + k * r)).Append(' ').Append(N(yt)).Append(' ').Append(N(x1)).Append(' ').Append(N(yt - r + k * r)).Append(' ').Append(N(x1)).Append(' ').Append(N(yt - r)).Append(" c ");
            cur.Append(N(x1)).Append(' ').Append(N(yb + r)).Append(" l ");
            cur.Append(N(x1)).Append(' ').Append(N(yb + r - k * r)).Append(' ').Append(N(x1 - r + k * r)).Append(' ').Append(N(yb)).Append(' ').Append(N(x1 - r)).Append(' ').Append(N(yb)).Append(" c ");
            cur.Append(N(x0 + r)).Append(' ').Append(N(yb)).Append(" l ");
            cur.Append(N(x0 + r - k * r)).Append(' ').Append(N(yb)).Append(' ').Append(N(x0)).Append(' ').Append(N(yb + r - k * r)).Append(' ').Append(N(x0)).Append(' ').Append(N(yb + r)).Append(" c ");
            cur.Append(N(x0)).Append(' ').Append(N(yt - r)).Append(" l ");
            cur.Append(N(x0)).Append(' ').Append(N(yt - r + k * r)).Append(' ').Append(N(x0 + r - k * r)).Append(' ').Append(N(yt)).Append(' ').Append(N(x0 + r)).Append(' ').Append(N(yt)).Append(" c h ");
        }

        public void FillRoundRect(double x, double y, double w, double h, double r, Rgb c)
        {
            cur.Append(c.Fill).Append(' ');
            RoundPath(x, y, w, h, r);
            cur.Append("f\n");
        }

        public void StrokeRoundRect(double x, double y, double w, double h, double r, Rgb c, double lineWidth)
        {
            cur.Append(c.Stroke).Append(' ').Append(N(lineWidth)).Append(" w ");
            RoundPath(x, y, w, h, r);
            cur.Append("S\n");
        }

        public void FillCircle(double cx, double cy, double r, Rgb c) { FillRoundRect(cx - r, cy - r, 2 * r, 2 * r, r, c); }

        /// <summary>Restricts drawing to a rectangle until <see cref="PopClip"/>.</summary>
        public void PushClip(double x, double y, double w, double h)
        {
            cur.Append("q ").Append(N(x)).Append(' ').Append(N(Y(y + h))).Append(' ').Append(N(w)).Append(' ').Append(N(h)).Append(" re W n\n");
        }

        public void PopClip() { cur.Append("Q\n"); }

        /// <summary>Draws text with its baseline at <paramref name="baseline"/> (from the top).</summary>
        public void Text(double x, double baseline, string s, PdfFont font, double size, Rgb c)
        {
            Text(x, baseline, s, font, size, c, 0);
        }

        public void Text(double x, double baseline, string s, PdfFont font, double size, Rgb c, double charSpacing)
        {
            if (string.IsNullOrEmpty(s)) return;
            cur.Append("BT /F").Append((int)font + 1).Append(' ').Append(N(size)).Append(" Tf ").Append(c.Fill).Append(' ');
            if (charSpacing != 0) cur.Append(N(charSpacing)).Append(" Tc ");
            cur.Append(N(x)).Append(' ').Append(N(Y(baseline))).Append(" Td (").Append(Escape(s)).Append(") Tj ");
            if (charSpacing != 0) cur.Append("0 Tc ");
            cur.Append("ET\n");
        }

        public void TextRight(double right, double baseline, string s, PdfFont font, double size, Rgb c)
        {
            Text(right - Measure(s, font, size), baseline, s, font, size, c);
        }

        // ------------------------------------------------------------ fonts

        private static readonly Encoding Win1252 = Encoding.GetEncoding(1252, new EncoderReplacementFallback("?"), new DecoderReplacementFallback("?"));

        private static byte[] Encode(string s)
        {
            if (s.IndexOf('✓') >= 0) s = s.Replace('✓', '*');
            return Win1252.GetBytes(s.Replace(' ', ' ').Replace('\t', ' '));
        }

        private static string Escape(string s)
        {
            var sb = new StringBuilder();
            foreach (byte b in Encode(s))
            {
                if (b == '(' || b == ')' || b == '\\') sb.Append('\\').Append((char)b);
                else if (b >= 32 && b < 127) sb.Append((char)b);
                else sb.Append('\\').Append(Convert.ToString(b, 8).PadLeft(3, '0'));
            }
            return sb.ToString();
        }

        // Adobe AFM advance widths (1/1000 em) for codes 32..126.
        private static readonly int[] HelvW = {
            278,278,355,556,556,889,667,191,333,333,389,584,278,333,278,278,
            556,556,556,556,556,556,556,556,556,556,278,278,584,584,584,556,
            1015,667,667,722,722,667,611,778,722,278,500,667,556,833,722,778,
            667,778,722,667,611,722,667,944,667,667,611,278,278,278,469,556,
            333,556,556,500,556,556,278,556,556,222,222,500,222,833,556,556,
            556,556,333,500,278,556,500,722,500,500,500,334,260,334,584 };
        private static readonly int[] HelvBW = {
            278,333,474,556,556,889,722,238,333,333,389,584,278,333,278,278,
            556,556,556,556,556,556,556,556,556,556,333,333,584,584,584,611,
            975,722,722,722,722,667,611,778,722,278,556,722,611,833,722,778,
            667,778,722,667,611,722,667,944,667,667,611,333,278,333,584,556,
            333,556,611,556,611,556,333,611,611,278,278,556,278,889,611,611,
            611,611,389,556,333,611,556,778,556,556,500,389,280,389,584 };

        private static int CharWidth(byte b, PdfFont f)
        {
            bool bold = f == PdfFont.Bold;
            if (b >= 32 && b <= 126) return bold ? HelvBW[b - 32] : HelvW[b - 32];
            switch (b)
            {
                case 0x95: return 350;                    // bullet
                case 0x96: return 556;                    // en dash
                case 0x97: return 1000;                   // em dash
                case 0x85: return 1000;                   // ellipsis
                case 0x91: case 0x92: return bold ? 278 : 222;
                case 0x93: case 0x94: return bold ? 500 : 333;
                case 0xB7: return 278;                    // middle dot
                case 0xB0: return 400;                    // degree
                case 0xD7: return 584;                    // multiplication sign
                default: return 556;
            }
        }

        public static double Measure(string s, PdfFont f, double size)
        {
            return Measure(s, f, size, 0);
        }

        public static double Measure(string s, PdfFont f, double size, double charSpacing)
        {
            if (string.IsNullOrEmpty(s)) return 0;
            byte[] bytes = Encode(s);
            double w = 0;
            foreach (byte b in bytes) w += CharWidth(b, f);
            return w * size / 1000.0 + charSpacing * bytes.Length;
        }

        /// <summary>Word-wraps text to a width, honouring explicit newlines and breaking over-long words.</summary>
        public static List<string> Wrap(string text, PdfFont f, double size, double width)
        {
            var lines = new List<string>();
            if (string.IsNullOrEmpty(text)) return lines;
            foreach (string para in text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n'))
            {
                string line = "";
                foreach (string rawWord in para.Split(' '))
                {
                    string word = rawWord;
                    string candidate = line.Length == 0 ? word : line + " " + word;
                    if (Measure(candidate, f, size) <= width) { line = candidate; continue; }
                    if (line.Length > 0) { lines.Add(line); line = ""; }
                    while (Measure(word, f, size) > width && word.Length > 1)
                    {
                        int n = word.Length - 1;
                        while (n > 1 && Measure(word.Substring(0, n), f, size) > width) n--;
                        lines.Add(word.Substring(0, n));
                        word = word.Substring(n);
                    }
                    line = word;
                }
                lines.Add(line);
            }
            return lines;
        }

        // ------------------------------------------------------------ output

        private static byte[] Zlib(byte[] data)
        {
            using (var ms = new MemoryStream())
            {
                ms.WriteByte(0x78); ms.WriteByte(0x9C);
                using (var ds = new DeflateStream(ms, CompressionMode.Compress, true)) ds.Write(data, 0, data.Length);
                uint a = 1, b = 0;
                foreach (byte x in data) { a = (a + x) % 65521; b = (b + a) % 65521; }
                uint adler = (b << 16) | a;
                ms.WriteByte((byte)(adler >> 24)); ms.WriteByte((byte)(adler >> 16)); ms.WriteByte((byte)(adler >> 8)); ms.WriteByte((byte)adler);
                return ms.ToArray();
            }
        }

        private static string PdfString(string s) { return "(" + Escape(s ?? "") + ")"; }

        public byte[] Save()
        {
            var output = new MemoryStream();
            var offsets = new List<long>();
            Action<string> write = s => { byte[] b = Encoding.ASCII.GetBytes(s); output.Write(b, 0, b.Length); };
            Action<int, string> obj = (n, body) => { offsets.Add(output.Position); write(n + " 0 obj\n" + body + "\nendobj\n"); };

            write("%PDF-1.4\n");
            output.Write(new byte[] { (byte)'%', 0xE2, 0xE3, 0xCF, 0xD3, (byte)'\n' }, 0, 6); // marks the file as binary
            int fontBase = 3, pageBase = 6;
            var kids = new StringBuilder();
            for (int i = 0; i < pages.Count; i++) kids.Append(pageBase + i * 2).Append(" 0 R ");

            obj(1, "<< /Type /Catalog /Pages 2 0 R >>");
            obj(2, "<< /Type /Pages /Kids [" + kids + "] /Count " + pages.Count + " >>");
            string[] names = { "Helvetica", "Helvetica-Bold", "Helvetica-Oblique" };
            for (int i = 0; i < 3; i++)
                obj(fontBase + i, "<< /Type /Font /Subtype /Type1 /BaseFont /" + names[i] + " /Encoding /WinAnsiEncoding >>");
            string resources = "<< /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >>";
            for (int i = 0; i < pages.Count; i++)
            {
                int pageObj = pageBase + i * 2, contentObj = pageObj + 1;
                obj(pageObj, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources " + resources + " /Contents " + contentObj + " 0 R >>");
                byte[] content = Zlib(Encoding.ASCII.GetBytes(pages[i].ToString()));
                offsets.Add(output.Position);
                write(contentObj + " 0 obj\n<< /Length " + content.Length + " /Filter /FlateDecode >>\nstream\n");
                output.Write(content, 0, content.Length);
                write("\nendstream\nendobj\n");
            }
            int infoObj = pageBase + pages.Count * 2;
            obj(infoObj, "<< /Title " + PdfString(Title) + " /Author " + PdfString(Author) + " /Subject " + PdfString(Subject) +
                " /Producer (Polarnite Server Audit Tool) /CreationDate (D:" + DateTime.Now.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture) + ") >>");

            long xref = output.Position;
            write("xref\n0 " + (offsets.Count + 1) + "\n0000000000 65535 f \n");
            foreach (long off in offsets) write(off.ToString("D10", CultureInfo.InvariantCulture) + " 00000 n \n");
            write("trailer\n<< /Size " + (offsets.Count + 1) + " /Root 1 0 R /Info " + infoObj + " 0 R >>\nstartxref\n" + xref + "\n%%EOF\n");
            return output.ToArray();
        }
    }
}
