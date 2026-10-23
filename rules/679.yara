rule Trojan_Win32_ClixkFix_NG_2147977831_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClixkFix.NG!MTB"
        threat_id = "2147977831"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClixkFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Start-Process powershell -ArgumentList @('-ExecutionPolicy', 'Bypass', '-File'" wide //weight: 1
        $x_1_2 = {24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00 [0-32] 2e 00 70 00 73 00 31 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
