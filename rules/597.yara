rule Trojan_Win32_Amynex_A_2147777774_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amynex.A"
        threat_id = "2147777774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amynex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = ").DownLoadString('http" wide //weight: 1
        $x_1_3 = {2e 00 70 00 68 00 70 00 3f 00 [0-2] 2e 00}  //weight: 1, accuracy: Low
        $x_1_4 = "*'+[Environment]::OSVersion.version.Major);bpu ('http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
