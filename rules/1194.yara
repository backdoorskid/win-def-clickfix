rule Trojan_Win32_PowExcEnv_RHA_2147957177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowExcEnv.RHA!MTB"
        threat_id = "2147957177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowExcEnv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-112] 24 00}  //weight: 10, accuracy: Low
        $x_10_2 = "::Frombase64string($" wide //weight: 10
        $x_10_3 = ".replace(''" wide //weight: 10
        $x_1_4 = ");iex $" wide //weight: 1
        $x_1_5 = ");invoke-expression $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}
