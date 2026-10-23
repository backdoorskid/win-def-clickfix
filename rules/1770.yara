rule Trojan_Win32_SusProxy_MK_2147954085_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.MK"
        threat_id = "2147954085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cscript.exe " ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "silence.vbs" ascii //weight: 1
        $x_1_4 = ".exe" wide //weight: 1
        $n_1_5 = "9453e881-26a8-4973-ba2e-76269e901d0t" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}
