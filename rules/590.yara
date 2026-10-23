rule Trojan_Win32_AmsiBypazz_GGA_2147948555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AmsiBypazz.GGA!MTB"
        threat_id = "2147948555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AmsiBypazz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "::GetExecutingAssembly" wide //weight: 1
        $x_1_2 = "System.Management.Automation.AmsiUtils" wide //weight: 1
        $x_1_3 = "System.Reflection.Assembly" wide //weight: 1
        $x_1_4 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
        $x_1_5 = "amsiInit" wide //weight: 1
        $x_1_6 = "GetField(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
