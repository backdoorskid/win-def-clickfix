rule Trojan_Win32_SusipicousMshatCMD_S02_2147933317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusipicousMshatCMD.S02"
        threat_id = "2147933317"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusipicousMshatCMD"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta" wide //weight: 1
        $n_10_2 = ".hta" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}
