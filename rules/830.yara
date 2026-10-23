rule Trojan_Win32_FileFix_HHC_2147950081_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.HHC!MTB"
        threat_id = "2147950081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".GetString($convert::FromBase64String" wide //weight: 1
        $x_1_2 = ";&(bitsadmin.exe /transfer " wide //weight: 1
        $x_1_3 = "join($env:TEMP" wide //weight: 1
        $x_1_4 = ".GetString($" wide //weight: 1
        $x_1_5 = ".GetBytes($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
