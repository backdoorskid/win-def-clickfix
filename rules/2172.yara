rule VirTool_Win32_UACBypassExp_D_2147852914_1
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
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_2_3 = {5c 00 6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_1_4 = "-MpPreference -Exclusion" wide //weight: 1
        $x_1_5 = " vbscript:Execute(" wide //weight: 1
        $x_1_6 = "];iex($" wide //weight: 1
        $x_1_7 = "ConsentPromptBehaviorAdmin -Value 0" wide //weight: 1
        $x_1_8 = {20 00 2f 00 76 00 20 00 2f 00 63 00 20 00 [0-8] 73 00 65 00 74 00 20 00 [0-8] 3d 00}  //weight: 1, accuracy: Low
        $x_1_9 = ").DownloadString(" wide //weight: 1
        $x_1_10 = {63 00 75 00 72 00 6c 00 [0-16] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_11 = "C:\\Users\\public\\" wide //weight: 1
        $x_1_12 = "\\AppData\\Roaming\\" wide //weight: 1
        $x_1_13 = {20 00 2d 00 65 00 20 00 22 80 80 0b 30 2d 39 41 2d 5a 61 2d 7a 2f 2b}  //weight: 1, accuracy: Low
        $x_1_14 = {20 00 2d 00 65 00 6e 00 20 00 22 80 80 0b 30 2d 39 41 2d 5a 61 2d 7a 2f 2b}  //weight: 1, accuracy: Low
        $x_1_15 = {20 00 2d 00 45 00 6e 00 63 00 6f 00 64 00 65 00 64 00 20 00 22 80 80 0b 30 2d 39 41 2d 5a 61 2d 7a 2f 2b}  //weight: 1, accuracy: Low
        $x_1_16 = "=[Ref].Assembly.GetType($((" wide //weight: 1
        $x_1_17 = " -ExclusionProcess powershell.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}
