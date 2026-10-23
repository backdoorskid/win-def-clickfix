rule Trojan_Win32_SupsPost_ZH_2147980372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SupsPost.ZH!MTB"
        threat_id = "2147980372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SupsPost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Net.WebClient" wide //weight: 1
        $x_1_2 = "DownloadString($" wide //weight: 1
        $x_1_3 = "[System.Convert].GetMethod($" wide //weight: 1
        $x_1_4 = ".Invoke($" wide //weight: 1
        $x_1_5 = "IO.MemoryStream(,$" wide //weight: 1
        $x_1_6 = "System.Drawing.Bitmap]::FromStream($" wide //weight: 1
        $x_1_7 = "-bor([" wide //weight: 1
        $x_1_8 = "AppDomain]::CurrentDomain.GetAssemblies" wide //weight: 1
        $x_1_9 = "System.Reflection.Assembly" wide //weight: 1
        $x_1_10 = ".CopyTo($" wide //weight: 1
        $x_1_11 = ".GetString($" wide //weight: 1
        $x_1_12 = "Invoke-Expression $" wide //weight: 1
        $x_1_13 = "IO.Compression.CompressionMode" wide //weight: 1
        $x_1_14 = "http" wide //weight: 1
        $n_10_15 = "\\Program Files" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}
