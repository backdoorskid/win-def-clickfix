rule Trojan_Win32_SuspProxy_P_2147955573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.P"
        threat_id = "2147955573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "rep_empoder.vbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
