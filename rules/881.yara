rule Trojan_Win32_Kovter_G_2147695443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kovter.G"
        threat_id = "2147695443"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kovter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 68 00 74 00 61 00 [0-16] 6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-255] 6e 00 65 00 77 00 20 00 61 00 63 00 74 00 69 00 76 00 65 00 78 00 6f 00 62 00 6a 00 65 00 63 00 74 00 28 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 00 73 00 68 00 74 00 61 00 [0-16] 6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-255] 67 00 65 00 74 00 6f 00 62 00 6a 00 65 00 63 00 74 00 28 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6d 00 73 00 68 00 74 00 61 00 [0-16] 76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-255] 65 00 78 00 65 00 63 00 75 00 74 00 65 00 28 00 [0-255] 67 00 65 00 74 00 6f 00 62 00 6a 00 65 00 63 00 74 00 28 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6d 00 73 00 68 00 74 00 61 00 [0-16] 76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-255] 65 00 78 00 65 00 63 00 75 00 74 00 65 00 28 00 [0-255] 63 00 72 00 65 00 61 00 74 00 65 00 6f 00 62 00 6a 00 65 00 63 00 74 00 28 00}  //weight: 1, accuracy: Low
        $n_50_5 = "Wscript.Shell\"\").Run \"\"robocopy.exe \"" wide //weight: -50
        $n_50_6 = "su8000005011.ad.ing.net\\DMLConfig\\FMO" wide //weight: -50
        $n_50_7 = "ffwin.fujifilm.co.jp\\netlogon" wide //weight: -50
        $n_50_8 = "util\\HpseuHostLAuncher.ps1" wide //weight: -50
        $n_50_9 = "MSHTA.EXE javascript:new ActiveXObject('Scripting.FileSystemObject').GetStandardStream(0).ReadAll()" wide //weight: -50
        $n_50_10 = "innerText=new ActiveXObject('Scripting.FileSystemObject').GetStandardStream(0).ReadAll()" wide //weight: -50
        $n_50_11 = {49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 29 00 2e 00 50 00 75 00 74 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 79 00 28 00 27 00 ?? ?? ?? ?? ?? ?? 27 00 2c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 29 00 3b 00 77 00 69 00 6e 00 64 00 6f 00 77 00 2e 00 72 00 65 00 73 00 69 00 7a 00 65 00 54 00 6f 00 28 00 35 00 30 00 30 00 2c 00 32 00 35 00 30 00 29 00 3b 00 77 00 69 00 6e 00 64 00 6f 00 77 00 2e 00 6d 00 6f 00 76 00 65 00 54 00 6f 00 28 00 2c 00 29 00}  //weight: -50, accuracy: Low
        $n_50_12 = "mshta vbscript:Execute(\"CreateObject(\"\"Wscript.shell\"\").run (\"\"powershell.exe -command net use H: \\\\filecl01fsh\\users$" wide //weight: -50
        $n_50_13 = "mshta.exe javascript:var sh=new ActiveXObject('WScript.Shell'); sh.Popup('" wide //weight: -50
        $n_50_14 = "vbscript:Execute(On Error Resume Next:call CreateObject(WSCript.shell).Run(%systemroot%\\system32\\reg.exe &amp" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}
