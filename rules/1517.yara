rule Trojan_Win32_Suspbxor_BF_2147980378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspbxor.BF!MTB"
        threat_id = "2147980378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspbxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SCRIPtblock]::CrEATe" wide //weight: 10
        $x_10_2 = "-bxor" wide //weight: 10
        $x_1_3 = "[convert]::frombase64string" wide //weight: 1
        $x_1_4 = "Net.WebClient).DownloadData" wide //weight: 1
        $x_1_5 = "[Text.Encoding]::ASCII.GetString((@(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}
