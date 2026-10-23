rule Trojan_Win32_BlueRabbit_GVVA_2147974264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlueRabbit.GVVA!MTB"
        threat_id = "2147974264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlueRabbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "80"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "-WindowStyle Hidden" wide //weight: 10
        $x_10_2 = "New-ScheduledTaskAction -Execute" wide //weight: 10
        $x_10_3 = "(Get-Date).AddSeconds(5)" wide //weight: 10
        $x_10_4 = "New-ScheduledTaskTrigger -AtStartup" wide //weight: 10
        $x_10_5 = "-LogonType S4U" wide //weight: 10
        $x_10_6 = "-RunLevel Highest" wide //weight: 10
        $x_10_7 = "-AllowStartIfOnBatteries" wide //weight: 10
        $x_10_8 = "-Hidden -RestartCount 3" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
