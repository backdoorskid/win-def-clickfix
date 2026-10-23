rule Trojan_Win32_ClixkFix_NJ_2147978268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClixkFix.NJ!MTB"
        threat_id = "2147978268"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClixkFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&call %" wide //weight: 1
        $x_1_2 = "|%comspec%" wide //weight: 1
        $x_1_3 = "start /min" wide //weight: 1
        $x_1_4 = "set " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
