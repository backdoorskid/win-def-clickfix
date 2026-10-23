rule VirTool_Win32_UACBypassExp_A_2147752130_5
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
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 00 72 00 65 00 67 00 2e 00 65 00 78 00 65 00 00 00 [0-96] 72 00 65 00 67 00 [0-8] 20 00 61 00 64 00 64 00 20 00 48 00 4b 00 45 00 59 00 5f 00 43 00 55 00 52 00 52 00 45 00 4e 00 54 00 5f 00 55 00 53 00 45 00 52 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 43 00 6c 00 61 00 73 00 73 00 65 00 73 00 5c 00 41 00 70 00 70 00 58 00 38 00 32 00 61 00 36 00 67 00 77 00 72 00 65 00 34 00 66 00 64 00 67 00 33 00 62 00 74 00 36 00 33 00 35 00 74 00 6e 00 35 00 63 00 74 00 71 00 6a 00 66 00 38 00 6d 00 73 00 64 00 64 00 32 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00}  //weight: 2, accuracy: Low
        $x_1_2 = " /d C:\\Windows\\system32\\cmd.exe /c start " wide //weight: 1
        $x_1_3 = " /t REG_SZ " wide //weight: 1
        $x_1_4 = " /f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
