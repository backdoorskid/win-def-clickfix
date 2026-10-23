rule Trojan_Win32_SuspExec_SV_2147977446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspExec.SV"
        threat_id = "2147977446"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {62 00 64 00 65 00 75 00 6e 00 6c 00 6f 00 63 00 6b 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "powershell" wide //weight: 1
        $x_1_3 = "iwr" wide //weight: 1
        $x_1_4 = "iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
