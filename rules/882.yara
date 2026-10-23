rule Trojan_Win32_Kovter_H_2147707267_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kovter.H"
        threat_id = "2147707267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kovter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-255] 6e 00 65 00 77 00 20 00 61 00 63 00 74 00 69 00 76 00 65 00 78 00 6f 00 62 00 6a 00 65 00 63 00 74 00 28 00 22 00 77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 73 00 68 00 65 00 6c 00 6c 00 22 00}  //weight: 1, accuracy: Low
        $x_10_2 = "RegRead(\"hkcu\\software" wide //weight: 10
        $n_50_3 = "Wscript.Shell\"\").Run \"\"robocopy.exe \"" wide //weight: -50
        $n_50_4 = "su8000005011.ad.ing.net\\DMLConfig\\FMO" wide //weight: -50
        $n_50_5 = "ffwin.fujifilm.co.jp\\netlogon\\webvpn_logon" wide //weight: -50
        $n_50_6 = "util\\HpseuHostLAuncher.ps1" wide //weight: -50
        $n_50_7 = "MSHTA.EXE javascript:new ActiveXObject('Scripting.FileSystemObject').GetStandardStream(0).ReadAll()" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}
