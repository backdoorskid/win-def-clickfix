rule VirTool_Win32_Magniber_C_2147842714_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Magniber.C"
        threat_id = "2147842714"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Magniber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wscript" wide //weight: 1
        $x_1_2 = "/E:VBScript.Encode" wide //weight: 1
        $x_1_3 = "../../Users/" wide //weight: 1
        $x_1_4 = "/B " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
