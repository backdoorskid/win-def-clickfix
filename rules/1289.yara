rule Trojan_Win32_RemoteSysDisc_A_2147768656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemoteSysDisc.A"
        threat_id = "2147768656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemoteSysDisc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_2_2 = "get-adcomputer" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
