rule Trojan_Win32_FileFix_EA_2147949392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.EA!MTB"
        threat_id = "2147949392"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "115"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Powershell" wide //weight: 100
        $x_10_2 = "='xyz';" wide //weight: 10
        $x_5_3 = " # " wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
