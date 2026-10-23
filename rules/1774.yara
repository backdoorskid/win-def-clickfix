rule Trojan_Win32_SusProxy_D_2147954109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.D"
        threat_id = "2147954109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" ascii //weight: 1
        $x_1_2 = "%PUBLICFILES%" ascii //weight: 1
        $x_1_3 = "mshtml" ascii //weight: 1
        $x_1_4 = "RunHTMLApplication" ascii //weight: 1
        $n_1_5 = "a453e881-26a8-4973-bs2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}
