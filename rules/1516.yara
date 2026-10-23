rule Trojan_Win32_Suspbxor_BE_2147980377_1
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
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System.Reflection.Assembly]::Load" wide //weight: 1
        $x_1_2 = "-bxor $" wide //weight: 1
        $x_1_3 = "[System.Convert]::FromBase64String" wide //weight: 1
        $x_1_4 = "[System.IO.File]::ReadAllText" wide //weight: 1
        $x_1_5 = "System.IO.MemoryStream" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
