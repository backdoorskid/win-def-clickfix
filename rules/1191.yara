rule Trojan_Win32_PowExcEnv_PB_2147948646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowExcEnv.PB!MTB"
        threat_id = "2147948646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowExcEnv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Add-MpPreference" wide //weight: 2
        $x_1_2 = "-ExclusionPath" wide //weight: 1
        $x_1_3 = "(Get-Location)" wide //weight: 1
        $x_1_4 = "-Force" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
