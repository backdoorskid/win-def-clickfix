rule Trojan_Win32_SuspLolbinLaunch_A_2147768658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLolbinLaunch.A!schtasks"
        threat_id = "2147768658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLolbinLaunch"
        severity = "Critical"
        info = "schtasks: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks.exe" wide //weight: 1
        $x_1_2 = "/create" wide //weight: 1
        $n_10_3 = "/run" wide //weight: -10
        $n_10_4 = "Diagnosis\\ZuumMonitoring" wide //weight: -10
        $n_10_5 = "AlertusSecureDesktopLauncher" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}
