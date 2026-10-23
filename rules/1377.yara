rule Trojan_Win32_Socgolsh_SJ_2147934465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Socgolsh.SJ"
        threat_id = "2147934465"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Socgolsh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks" wide //weight: 1
        $x_1_2 = "ssh.exe" wide //weight: 1
        $x_1_3 = "StrictHostKeyChecking=no" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
