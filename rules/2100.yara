rule VirTool_Win32_SuspMsiExec_D_2147967780_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspMsiExec.D"
        threat_id = "2147967780"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspMsiExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = "/download?id=" wide //weight: 1
        $x_1_3 = "&export=download" wide //weight: 1
        $x_1_4 = "&confirm=t" wide //weight: 1
        $x_1_5 = "&uuid=" wide //weight: 1
        $x_1_6 = " /i " wide //weight: 1
        $x_1_7 = " /qn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
