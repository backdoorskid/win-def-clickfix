rule VirTool_Win32_UACBypassExp_D_2147852914_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/UACBypassExp.gen!D"
        threat_id = "2147852914"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "UACBypassExp"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 57 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 00 6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "-MpPreference -Exclusion" wide //weight: 1
        $x_1_7 = " vbscript:Execute(" wide //weight: 1
        $x_1_8 = "C:\\Users\\public\\" wide //weight: 1
        $x_1_9 = "\\AppData\\Roaming\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}
