rule Trojan_Win32_SusProxy_F_2147954111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.F"
        threat_id = "2147954111"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = "timeout" ascii //weight: 1
        $x_1_3 = "tasklist /svc" ascii //weight: 1
        $x_1_4 = "findstr /i" ascii //weight: 1
        $n_1_5 = "a453e881-26a8-4973-bu2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (2 of ($x*))
}
