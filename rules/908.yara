rule Trojan_Win32_LummaStealerClick_H_2147932737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.H"
        threat_id = "2147932737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "net.webclient" wide //weight: 10
        $x_10_3 = "[system.reflection.assembly]::load($" wide //weight: 10
        $x_10_4 = ".invoke($" wide //weight: 10
        $x_10_5 = ".headers.add($" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
