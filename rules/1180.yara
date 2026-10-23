rule Trojan_Win32_Powessere_Q_2147775271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.Q"
        threat_id = "2147775271"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "mshta" wide //weight: 1
        $x_1_2 = "vbscript:Execute" wide //weight: 1
        $x_1_3 = ").Run" wide //weight: 1
        $x_1_4 = "powershell" wide //weight: 1
        $x_1_5 = "Invoke-Expression" wide //weight: 1
        $x_1_6 = "iwr -uri " wide //weight: 1
        $x_1_7 = {2e 00 70 00 68 00 70 00 20 00 2d 00 6d 00 65 00 74 00 68 00 6f 00 64 00 20 00 70 00 6f 00 73 00 74 00 20 00 2d 00 62 00 6f 00 64 00 79 00 20 00 [0-32] 29 00 2e 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
