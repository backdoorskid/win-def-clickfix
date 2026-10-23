rule Trojan_Win32_Suspbxor_BN_2147980396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspbxor.BN!MTB"
        threat_id = "2147980396"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspbxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-bxor $" wide //weight: 1
        $x_1_2 = "scriptblock]::Create(" wide //weight: 1
        $x_1_3 = "GetString($" wide //weight: 1
        $x_1_4 = "DownloadData" wide //weight: 1
        $x_1_5 = "WebClient" wide //weight: 1
        $x_1_6 = "[byte]0x" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
