rule Ransom_Win32_DeleteShadows_A_2147818400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DeleteShadows.A"
        threat_id = "2147818400"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DeleteShadows"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" wide //weight: 1
        $x_1_2 = "vssadmin.exe delete shadows /all /quiet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
