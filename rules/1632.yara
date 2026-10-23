rule Trojan_Win32_SuspLoad_BA_2147980380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLoad.BA!MTB"
        threat_id = "2147980380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Reflection.Assembly]::Load" wide //weight: 1
        $x_1_2 = "|%{[int]$_" wide //weight: 1
        $x_1_3 = ").Split('|')" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
