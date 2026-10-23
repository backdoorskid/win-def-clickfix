rule Trojan_PowerShell_LemonDuck_B_2147777719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/LemonDuck.B"
        threat_id = "2147777719"
        type = "Trojan"
        platform = "PowerShell: "
        family = "LemonDuck"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell -w" wide //weight: 1
        $x_1_2 = "hidden" wide //weight: 1
        $x_1_3 = "[System.Text.Encoding]::ASCII.GetString" wide //weight: 1
        $x_3_4 = {2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 44 00 61 00 74 00 61 00 28 00 27 00 68 00 74 00 74 00 70 00 [0-48] 2f 00 61 00 2e 00 6a 00 73 00 70 00 3f 00}  //weight: 3, accuracy: Low
        $x_1_5 = "$env:COMPUTERNAME,$env:USERNAME" wide //weight: 1
        $x_1_6 = "(get-wmiobject Win32_ComputerSystemProduct).UUID" wide //weight: 1
        $x_1_7 = "(random))-join'*'))" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}
