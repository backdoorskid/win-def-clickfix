rule Trojan_Win32_SuspProxy_D_2147954129_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.D"
        threat_id = "2147954129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" ascii //weight: 1
        $x_1_2 = "%PUBLICFILES%" ascii //weight: 1
        $x_1_3 = "mshtml" ascii //weight: 1
        $x_1_4 = "RunHTMLApplication" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
