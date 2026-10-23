rule Trojan_Win32_Dexphot_2147731153_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dexphot"
        threat_id = "2147731153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dexphot"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Headers['User-Agent'] = 'Windows Installer'" wide //weight: 1
        $x_1_2 = ".DownloadFile('http" wide //weight: 1
        $x_1_3 = ".info/" wide //weight: 1
        $x_1_4 = "Start-Process " wide //weight: 1
        $x_1_5 = "-ArgumentList '/q" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
