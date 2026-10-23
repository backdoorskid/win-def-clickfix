rule Trojan_Win32_UacBypass_PB_2147952188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UacBypass.PB!MTB"
        threat_id = "2147952188"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UacBypass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "schtasks /Run /i /TN" wide //weight: 2
        $x_1_2 = "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
