rule Trojan_Win32_Kalavus_B_2147955838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kalavus.B"
        threat_id = "2147955838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kalavus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "\\valakmalware_text.txt" wide //weight: 1
        $x_1_3 = "wget" wide //weight: 1
        $x_1_4 = " -o " wide //weight: 1
        $x_1_5 = "wscript.exe" wide //weight: 1
        $x_1_6 = "//E:jscript" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
