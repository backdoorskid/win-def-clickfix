rule Trojan_Win32_FileFix_HHA_2147950079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.HHA!MTB"
        threat_id = "2147950079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iex(irm $" wide //weight: 1
        $x_1_2 = ";iex $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
