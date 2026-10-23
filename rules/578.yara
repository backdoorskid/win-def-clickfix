rule Trojan_Win32_Amadey_Z_2147941857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.Z!MTB"
        threat_id = "2147941857"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".EntryPoint.Invoke($" wide //weight: 1
        $x_1_2 = "[Char](" wide //weight: 1
        $x_1_3 = ".GetValue(" wide //weight: 1
        $x_1_4 = "[Reflection.Assembly]::Load" wide //weight: 1
        $x_1_5 = "Runtime.InteropServices.Marshal]" wide //weight: 1
        $x_1_6 = "split" wide //weight: 1
        $x_1_7 = ".GetMethod(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
