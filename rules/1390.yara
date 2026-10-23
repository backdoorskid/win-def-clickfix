rule Trojan_Win32_SupsPost_ZB_2147979642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SupsPost.ZB!MTB"
        threat_id = "2147979642"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SupsPost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "io.memorystream;$" wide //weight: 1
        $x_1_2 = "[convert]::frombase64string($" wide //weight: 1
        $x_1_3 = "-bxor $" wide //weight: 1
        $x_1_4 = ".Invoke($null,@(,[byte[]](" wide //weight: 1
        $x_1_5 = ".GetMethod('Load" wide //weight: 1
        $x_1_6 = "System.Reflection.Assembly" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
