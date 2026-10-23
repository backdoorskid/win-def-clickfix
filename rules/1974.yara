rule Trojan_Win32_VaultCredentials_B_2147815169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VaultCredentials.B"
        threat_id = "2147815169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VaultCredentials"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vaultcmd.exe /listcreds:" ascii //weight: 1
        $x_1_2 = "vaultcmd /listcreds:" ascii //weight: 1
        $x_1_3 = "vaultcmd.exe /list" ascii //weight: 1
        $x_1_4 = "vaultcmd /list" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}
