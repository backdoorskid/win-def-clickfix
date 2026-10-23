rule Trojan_Win32_Tayekut_F_2147796283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tayekut.F"
        threat_id = "2147796283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tayekut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 68 00 74 00 61 00 [0-16] 76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00}  //weight: 1, accuracy: Low
        $x_1_2 = "createobject(" wide //weight: 1
        $x_1_3 = "wscript.shell" wide //weight: 1
        $x_1_4 = ".run" wide //weight: 1
        $x_1_5 = "powershell" wide //weight: 1
        $x_1_6 = "invoke-webrequest" wide //weight: 1
        $x_1_7 = ":close)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
