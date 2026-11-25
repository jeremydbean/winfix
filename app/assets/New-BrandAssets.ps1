<#
.SYNOPSIS
Makes the app's brand assets from the Polarnite logo (white wordmark + round badge, for dark backgrounds):
  polarnite-logo.png   trimmed full logo (app header, PDF cover)
  polarnite-badge.png  the round "nITe services" badge, 256 px (PDF page headers)
  polarnite.ico        exe icon from the badge (16-256 px)
Source: https://polarnite.com/wp-content/uploads/2022/03/polar-nite-dark-background.png
#>
param([Parameter(Mandatory = $true)][string]$Source)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }

function Get-Bounds([System.Drawing.Bitmap]$bmp, [int]$minX) {
    $rect = New-Object System.Drawing.Rectangle 0, 0, $bmp.Width, $bmp.Height
    $data = $bmp.LockBits($rect, 'ReadOnly', 'Format32bppArgb')
    $bytes = New-Object byte[] ($data.Stride * $bmp.Height)
    [Runtime.InteropServices.Marshal]::Copy($data.Scan0, $bytes, 0, $bytes.Length)
    $bmp.UnlockBits($data)
    $l = $bmp.Width; $t = $bmp.Height; $r = -1; $b = -1
    for ($y = 0; $y -lt $bmp.Height; $y++) {
        $row = $y * $data.Stride
        for ($x = $minX; $x -lt $bmp.Width; $x++) {
            if ($bytes[$row + $x * 4 + 3] -gt 16) {
                if ($x -lt $l) { $l = $x }; if ($x -gt $r) { $r = $x }; if ($y -lt $t) { $t = $y }; if ($y -gt $b) { $b = $y }
            }
        }
    }
    New-Object System.Drawing.Rectangle $l, $t, ($r - $l + 1), ($b - $t + 1)
}

function Get-Resized([System.Drawing.Image]$src, [System.Drawing.Rectangle]$from, [int]$w, [int]$h) {
    $out = New-Object System.Drawing.Bitmap $w, $h, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($out)
    $g.InterpolationMode = 'HighQualityBicubic'; $g.PixelOffsetMode = 'HighQuality'; $g.SmoothingMode = 'HighQuality'
    $g.DrawImage($src, (New-Object System.Drawing.Rectangle 0, 0, $w, $h), $from, 'Pixel')
    $g.Dispose()
    $out
}

$src = New-Object System.Drawing.Bitmap $Source
try {
    # Full logo, trimmed, at most 800 px wide.
    $all = Get-Bounds $src 0
    $w = [Math]::Min(800, $all.Width); $h = [int][Math]::Round($all.Height * $w / $all.Width)
    $logo = Get-Resized $src $all $w $h
    $logo.Save((Join-Path $here 'polarnite-logo.png'), [System.Drawing.Imaging.ImageFormat]::Png); $logo.Dispose()

    # Badge: the round part on the right, made square.
    $circle = Get-Bounds $src ([int]($src.Width * 0.46))
    $side = [Math]::Max($circle.Width, $circle.Height)
    $square = New-Object System.Drawing.Rectangle ($circle.X - [int](($side - $circle.Width) / 2)), ($circle.Y - [int](($side - $circle.Height) / 2)), $side, $side
    $badge = Get-Resized $src $square 256 256
    $badge.Save((Join-Path $here 'polarnite-badge.png'), [System.Drawing.Imaging.ImageFormat]::Png)

    # Icon: PNG-compressed entries (Windows Vista / Server 2008 and later).
    $sizes = 16, 20, 24, 32, 40, 48, 64, 128, 256
    $pngs = foreach ($s in $sizes) {
        $img = Get-Resized $badge (New-Object System.Drawing.Rectangle 0, 0, 256, 256) $s $s
        $ms = New-Object IO.MemoryStream; $img.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png); $img.Dispose()
        , $ms.ToArray()
    }
    $badge.Dispose()
    $ico = New-Object IO.MemoryStream; $bw = New-Object IO.BinaryWriter $ico
    $bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$sizes.Count)
    $offset = 6 + 16 * $sizes.Count
    for ($i = 0; $i -lt $sizes.Count; $i++) {
        $s = $sizes[$i]; $dim = if ($s -ge 256) { 0 } else { $s }
        $bw.Write([byte]$dim); $bw.Write([byte]$dim); $bw.Write([byte]0); $bw.Write([byte]0)
        $bw.Write([uint16]1); $bw.Write([uint16]32); $bw.Write([uint32]$pngs[$i].Length); $bw.Write([uint32]$offset)
        $offset += $pngs[$i].Length
    }
    foreach ($p in $pngs) { $bw.Write($p) }
    $bw.Flush(); [IO.File]::WriteAllBytes((Join-Path $here 'polarnite.ico'), $ico.ToArray())
} finally { $src.Dispose() }
Get-ChildItem $here -Include *.png, *.ico -Recurse | Select-Object Name, Length
