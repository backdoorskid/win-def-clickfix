rule Trojan_Win32_Powemet_E_2147729715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powemet.E"
        threat_id = "2147729715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powemet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = "bypass" wide //weight: 1
        $x_1_3 = "hidden" wide //weight: 1
        $x_1_4 = "-encoded" wide //weight: 1
        $x_3_5 = "SQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoALgBwAHMAMQA" wide //weight: 3
        $x_3_6 = "AEkAbgB2AG8AawBlAC0ATQBpAG0AaQBrAGEAdAB6AC4AcABzADEA" wide //weight: 3
        $x_3_7 = "cwBlAGsAdQByAGwAcwBhADoAOg" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}
