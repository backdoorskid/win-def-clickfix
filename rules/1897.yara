rule Trojan_Win32_SusSparrow_C_2147954096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusSparrow.C"
        threat_id = "2147954096"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusSparrow"
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
        $n_1_7 = "a453e881-26a8-4973-bf2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}
