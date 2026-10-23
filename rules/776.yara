rule Trojan_Win32_Dexphot_P_2147735858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dexphot.P"
        threat_id = "2147735858"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dexphot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Headers['User-Agent'] = 'Windows Installer'" wide //weight: 1
        $x_1_2 = ".DownloadFile('http" wide //weight: 1
        $x_1_3 = ".info/" wide //weight: 1
        $x_1_4 = "\\dump007.dat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}
