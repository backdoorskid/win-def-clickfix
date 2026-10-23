rule Trojan_Win32_Powessere_I_2147726501_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.I"
        threat_id = "2147726501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = "Invoke-Expression ([System.Text.Encoding]::ASCII.GetString((Get-ItemProperty HKCU:Software\\AppDataLow\\Software\\Microsoft\\" wide //weight: 1
        $x_1_3 = {29 00 2e 00 [0-32] 29 00 29 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
