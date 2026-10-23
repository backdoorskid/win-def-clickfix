rule Trojan_Win32_Tayekut_D_2147763301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tayekut.D"
        threat_id = "2147763301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tayekut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 68 00 74 00 61 00 [0-16] 76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00}  //weight: 1, accuracy: Low
        $x_1_2 = "createobject(" wide //weight: 1
        $x_1_3 = "wscript.shell" wide //weight: 1
        $x_1_4 = {2e 00 72 00 75 00 6e 00 28 00 [0-255] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = "window.close" wide //weight: 1
        $n_20_6 = {2e 00 72 00 75 00 6e 00 28 00 90 00 02 00 ff 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00}  //weight: -20, accuracy: High
        $n_20_7 = {2e 00 72 00 75 00 6e 00 28 00 90 00 02 00 ff 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00}  //weight: -20, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}
