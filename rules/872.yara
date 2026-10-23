rule Trojan_Win32_JScealTaskExec_AA_2147967451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/JScealTaskExec.AA"
        threat_id = "2147967451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "JScealTaskExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = " -e" wide //weight: 1
        $x_1_3 = "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARQB4AGMAbAB1AHMAaQBv" wide //weight: 1
        $x_1_4 = "AG4AUABhAHQAaAAgACgARwBlAHQALQBMAG8AYwBhAHQAaQBvAG4AKQAgAC0ARgBvAHIAYwBlAA==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
