rule Trojan_Win32_Ofisus_A_2147731060_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ofisus.A"
        threat_id = "2147731060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ofisus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\cmd.exe" wide //weight: 1
        $x_1_2 = "cmd /c powershell" wide //weight: 1
        $x_1_3 = ").downloadfile($" wide //weight: 1
        $x_1_4 = "''%tmp%\\" wide //weight: 1
        $x_1_5 = "'');start-process" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
