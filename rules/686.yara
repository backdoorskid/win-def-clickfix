rule Trojan_Win32_ClixkFix_NM_2147978271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClixkFix.NM!MTB"
        threat_id = "2147978271"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClixkFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Content|powershell" wide //weight: 1
        $x_1_2 = "hidden" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
