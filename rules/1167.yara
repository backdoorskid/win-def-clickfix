rule Trojan_Win32_Powessere_H_2147726088_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.H"
        threat_id = "2147726088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta" wide //weight: 1
        $x_1_2 = "about:<hta:application><script>" wide //weight: 1
        $x_1_3 = "resizeTo(1,1)" wide //weight: 1
        $x_1_4 = "eval(new ActiveXObject('WScript.Shell').RegRead('HKCU\\\\Software\\\\AppDataLow\\\\Software\\\\Microsoft\\\\" wide //weight: 1
        $x_1_5 = "if(!window.flag)close()" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
