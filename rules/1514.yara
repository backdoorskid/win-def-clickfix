rule Trojan_Win32_Suspbxor_BD_2147980376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspbxor.BD!MTB"
        threat_id = "2147980376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspbxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Replace(" wide //weight: 1
        $x_1_2 = " System.IO.MemoryStream;$" wide //weight: 1
        $x_1_3 = "-bxor " wide //weight: 1
        $x_1_4 = "[System.Reflection.Assembly]::$" wide //weight: 1
        $x_1_5 = "System.Convert]::$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
