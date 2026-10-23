rule VirTool_Win32_UACBypassExp_A_2147752130_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/UACBypassExp.A"
        threat_id = "2147752130"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "UACBypassExp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = " -w hidden " wide //weight: 1
        $x_1_3 = {49 00 65 00 78 00 [0-96] 2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
