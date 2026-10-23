rule Trojan_Win32_AmsiBypass_ZZ_2147979207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AmsiBypass.ZZ!MTB"
        threat_id = "2147979207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AmsiBypass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Convert]::FromBase64String($" wide //weight: 1
        $x_1_2 = "IO.MemoryStream" wide //weight: 1
        $x_1_3 = "::Load($" wide //weight: 1
        $x_1_4 = "byte[]" wide //weight: 1
        $x_1_5 = "amsi.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
