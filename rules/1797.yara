rule Trojan_Win32_SuspSetting_E_2147955604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSetting.E"
        threat_id = "2147955604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSetting"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c set" ascii //weight: 1
        $x_1_2 = "hostname.exe" ascii //weight: 1
        $x_1_3 = "qprocess" ascii //weight: 1
        $x_1_4 = "cmd.exe /c ver" ascii //weight: 1
        $x_1_5 = "cmd.exe /c systeminfo | findstr /B /C:OS Name /C:OS Version" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}
