rule Trojan_Win32_SuspSetting_H_2147955607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSetting.H"
        threat_id = "2147955607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSetting"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "New-Object" ascii //weight: 1
        $x_1_3 = "System.Threading.Mutex(" ascii //weight: 1
        $x_1_4 = "Dispose()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
