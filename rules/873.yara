rule Trojan_Win32_JScealTaskExec_AB_2147967452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/JScealTaskExec.AB"
        threat_id = "2147967452"
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
        $x_1_3 = "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARQB4AGMAbAB1AHMAaQBvAG4AUAByAG8AYwBlAHMAcwAgACgARwBlAHQALQBQAH" wide //weight: 1
        $x_1_4 = "IAbwBjAGUAcwBzACAALQBQAEkARAAgACQAUABJAEQAKQAuAE0AYQBpAG4ATQBvAGQAdQBsAGUALgBNAG8AZAB1AGwAZQBOAGEAbQBlACAALQBGAG8AcgBjAGUA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
