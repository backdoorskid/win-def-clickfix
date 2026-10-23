rule VirTool_Win32_Magniber_D_2147844870_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Magniber.D"
        threat_id = "2147844870"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Magniber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "wscript" wide //weight: 1
        $x_1_2 = "/E:VBScript.Encode" wide //weight: 1
        $x_1_3 = "../../Users/" wide //weight: 1
        $x_1_4 = "/B " wide //weight: 1
        $n_10_5 = {2e 00 2e 00 2f 00 2e 00 2e 00 2f 00 75 00 73 00 65 00 72 00 73 00 2f 00 [0-255] 2e 00 76 00 62 00 73 00}  //weight: -10, accuracy: Low
        $n_10_6 = {2e 00 2e 00 2f 00 2e 00 2e 00 2f 00 75 00 73 00 65 00 72 00 73 00 2f 00 [0-255] 2e 00 76 00 62 00 65 00}  //weight: -10, accuracy: Low
        $n_10_7 = {2e 00 2e 00 2f 00 2e 00 2e 00 2f 00 75 00 73 00 65 00 72 00 73 00 2f 00 [0-255] 2e 00 6a 00 73 00}  //weight: -10, accuracy: Low
        $n_10_8 = {2e 00 2e 00 2f 00 2e 00 2e 00 2f 00 75 00 73 00 65 00 72 00 73 00 2f 00 [0-255] 2e 00 6a 00 73 00 65 00}  //weight: -10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}
