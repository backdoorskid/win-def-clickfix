rule Trojan_Win32_SuspClickFix_R_2147962996_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.R"
        threat_id = "2147962996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "nslookup" wide //weight: 5
        $x_1_2 = " | findstr ^Name:" wide //weight: 1
        $x_1_3 = " | findstr powershell" wide //weight: 1
        $x_1_4 = " | for /f" wide //weight: 1
        $x_1_5 = "tokens=" wide //weight: 1
        $x_1_6 = "delims=" wide //weight: 1
        $x_1_7 = " | cmd" wide //weight: 1
        $x_1_8 = " | C:\\Windows\\System32\\cmd.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}
