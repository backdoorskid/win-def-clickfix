rule Trojan_Win32_SuspClickFix_Q3_2147967020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.Q3"
        threat_id = "2147967020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " && curl " wide //weight: 1
        $x_1_2 = " && tar -xf" wide //weight: 1
        $x_1_3 = " /c mkdir " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
