rule Trojan_Win32_PowExcEnv_PA_2147948645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowExcEnv.PA!MTB"
        threat_id = "2147948645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowExcEnv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Add-MpPreference" wide //weight: 2
        $x_1_2 = "-ExclusionProcess" wide //weight: 1
        $x_1_3 = "Get-Process -PID" wide //weight: 1
        $x_1_4 = "MainModule.ModuleName" wide //weight: 1
        $x_1_5 = "-Force" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
