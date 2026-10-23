rule Trojan_Win32_Dexphot_CB_2147735854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dexphot.CB"
        threat_id = "2147735854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dexphot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 65 00 78 00 65 00 20 00 [0-32] 2d 00 69 00 [0-16] 20 00 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 00 65 00 78 00 65 00 20 00 [0-32] 2f 00 69 00 [0-16] 20 00 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 00 65 00 78 00 65 00 22 00 20 00 [0-32] 2d 00 69 00 [0-16] 20 00 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 00 65 00 78 00 65 00 22 00 20 00 [0-32] 2f 00 69 00 [0-16] 20 00 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $n_10_5 = "youtube-dl.exe" wide //weight: -10
        $n_10_6 = "ffmpeg.exe" wide //weight: -10
        $n_10_7 = "curl.exe" wide //weight: -10
        $n_10_8 = "vstoinstaller.exe" wide //weight: -10
        $n_10_9 = "microsoft.com" wide //weight: -10
        $n_10_10 = "/feedstation/" wide //weight: -10
        $n_10_11 = "=updateindex" wide //weight: -10
        $n_10_12 = "/iplog.php?" wide //weight: -10
        $n_10_13 = "/default.aspx?" wide //weight: -10
        $n_10_14 = "localhost" wide //weight: -10
        $n_10_15 = ".co.kr" wide //weight: -10
        $n_10_16 = ".cf/" wide //weight: -10
        $n_10_17 = "cleveraccounts.com" wide //weight: -10
        $n_10_18 = "syncfx.com" wide //weight: -10
        $n_10_19 = "pass-pdam.com" wide //weight: -10
        $n_10_20 = "screengrab.exe" wide //weight: -10
        $n_10_21 = "UpdatEngine" wide //weight: -10
        $n_10_22 = "powershell" ascii //weight: -10
        $n_10_23 = "cisco" ascii //weight: -10
        $n_10_24 = "w3wp.exe" ascii //weight: -10
        $n_10_25 = "Vajasoft.Inventory.exe" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}
