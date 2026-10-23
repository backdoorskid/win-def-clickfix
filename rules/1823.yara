rule Trojan_Win32_SuspSparrow_C_2147955561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSparrow.C"
        threat_id = "2147955561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSparrow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks.exe /create /sc daily /tn" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "Microsoft\\Windows\\Power" ascii //weight: 1
        $x_1_4 = "/ST" wide //weight: 1
        $x_1_5 = "/tr" wide //weight: 1
        $x_1_6 = "/F" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
