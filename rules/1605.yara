rule Trojan_Win32_SuspExec_SB_2147940113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspExec.SB"
        threat_id = "2147940113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "mshta.exe" wide //weight: 5
        $x_5_2 = "vbscript:execute(" wide //weight: 5
        $x_5_3 = "powershell" wide //weight: 5
        $x_5_4 = "strreverse" wide //weight: 5
        $x_5_5 = "llehS.tpircsW" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}
