rule Trojan_Win32_SuspProxyExecution_D_2147940643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxyExecution.D"
        threat_id = "2147940643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxyExecution"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ">nul & msiexec /i" ascii //weight: 1
        $x_1_2 = "dll_path=" ascii //weight: 1
        $x_1_3 = "/passive &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
