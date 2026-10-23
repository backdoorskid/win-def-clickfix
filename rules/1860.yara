rule Trojan_Win32_SusReg_D_2147955598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusReg.D"
        threat_id = "2147955598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusReg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c systeminfo" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp\\temp.ini" ascii //weight: 1
        $x_1_3 = "tasklist" ascii //weight: 1
        $x_1_4 = "makecab" ascii //weight: 1
        $x_1_5 = "temp.cab" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
