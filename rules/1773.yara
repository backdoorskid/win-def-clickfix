rule Trojan_Win32_SusProxy_C_2147954108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.C"
        threat_id = "2147954108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "conhost.exe" ascii //weight: 1
        $x_1_2 = "notepad.exe" ascii //weight: 1
        $n_1_3 = "a453e881-26a8-4973-br2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}
