rule Trojan_Win32_Stealz_ZCT_2147943076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealz.ZCT!MTB"
        threat_id = "2147943076"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Add-Type -AssemblyName System.Security" wide //weight: 1
        $x_1_2 = "::Unprotect([System.Convert]::FromBase64String(" wide //weight: 1
        $x_1_3 = "[System.Security.Cryptography.DataProtectionScope]::CurrentUser)" wide //weight: 1
        $x_1_4 = "$null" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
