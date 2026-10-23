rule Trojan_Win32_JScealTaskExec_EB_2147969477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/JScealTaskExec.EB"
        threat_id = "2147969477"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "JScealTaskExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = " -Command iex (iwr -useb " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
