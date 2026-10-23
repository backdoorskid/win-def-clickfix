rule Trojan_Win32_PowExcEnv_PD_2147970742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowExcEnv.PD!MTB"
        threat_id = "2147970742"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowExcEnv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "powershell" wide //weight: 5
        $x_1_2 = ") 2>$null" wide //weight: 1
        $x_1_3 = "iex ($" wide //weight: 1
        $x_1_4 = ".DownloadString(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
