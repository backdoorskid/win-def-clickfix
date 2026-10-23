rule Trojan_Win32_SuspSparrow_MK_2147955558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSparrow.MK"
        threat_id = "2147955558"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSparrow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c " ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "update.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
