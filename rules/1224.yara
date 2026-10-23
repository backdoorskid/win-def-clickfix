rule Trojan_Win32_PShellDlr_PA_2147934093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellDlr.PA!MTB"
        threat_id = "2147934093"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellDlr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "New-NetFirewallRule -DisplayName" wide //weight: 1
        $x_1_3 = "Windows Update" wide //weight: 1
        $x_2_4 = {2d 00 52 00 65 00 6d 00 6f 00 74 00 65 00 41 00 64 00 64 00 72 00 65 00 73 00 73 00 20 00 [0-48] 20 00 2d 00 50 00 72 00 6f 00 74 00 6f 00 63 00 6f 00 6c 00 20 00 54 00 43 00 50 00 20 00 2d 00 41 00 63 00 74 00 69 00 6f 00 6e 00 20 00 41 00 6c 00 6c 00 6f 00 77 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
