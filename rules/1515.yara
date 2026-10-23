rule Trojan_Win32_Suspbxor_BE_2147980377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspbxor.BE!MTB"
        threat_id = "2147980377"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspbxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "([SCRIPtblock]::CrEATe($" wide //weight: 1
        $x_1_2 = "::fRoMBAse64STRiNg($" wide //weight: 1
        $x_1_3 = ".' + '" wide //weight: 1
        $x_1_4 = "-bxor" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
