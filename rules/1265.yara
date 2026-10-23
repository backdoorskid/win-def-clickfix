rule Trojan_Win32_Redaman_A_2147734374_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redaman.A"
        threat_id = "2147734374"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redaman"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" wide //weight: 1
        $x_1_2 = "c:\\programdata\\" wide //weight: 1
        $x_1_3 = "dllgetclassobject host" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
