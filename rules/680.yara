rule Trojan_Win32_ClixkFix_NI_2147977832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClixkFix.NI!MTB"
        threat_id = "2147977832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClixkFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "('powershell -ep bypass -f '+[char]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
