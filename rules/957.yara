rule Trojan_Win32_Mesdetty_D_2147821891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mesdetty.D"
        threat_id = "2147821891"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mesdetty"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {5c 00 6d 00 73 00 64 00 74 00 [0-240] 70 00 63 00 77 00 64 00 69 00 61 00 67 00 6e 00 6f 00 73 00 74 00 69 00 63 00}  //weight: 100, accuracy: Low
        $x_1_2 = "invoke-expression" wide //weight: 1
        $x_1_3 = "iex " wide //weight: 1
        $x_1_4 = "FromBase64String" wide //weight: 1
        $x_1_5 = "mpsigstub.exe" wide //weight: 1
        $x_1_6 = "cal?c" wide //weight: 1
        $x_1_7 = "calc" wide //weight: 1
        $x_1_8 = "notepad" wide //weight: 1
        $x_1_9 = "browseforfile" wide //weight: 1
        $x_1_10 = "Start-Process" wide //weight: 1
        $x_1_11 = "IT_RebrowseForFile=?" wide //weight: 1
        $x_1_12 = "\\localhost\\" wide //weight: 1
        $x_1_13 = "%5C%5Clocalhost" wide //weight: 1
        $x_1_14 = "+[char]58+" wide //weight: 1
        $x_1_15 = "/../../" wide //weight: 1
        $x_1_16 = "\\..\\..\\" wide //weight: 1
        $x_1_17 = "%20IT_" wide //weight: 1
        $x_1_18 = {72 00 6f 00 77 00 73 00 65 00 46 00 6f 00 72 00 46 00 69 00 6c 00 65 00 3d 00 [0-80] 3f 00}  //weight: 1, accuracy: Low
        $x_1_19 = "file=h'" wide //weight: 1
        $x_1_20 = "file=h`" wide //weight: 1
        $x_1_21 = "file=h\"" wide //weight: 1
        $x_1_22 = "file=h$" wide //weight: 1
        $x_1_23 = "/hi'" wide //weight: 1
        $x_1_24 = "/hi\"" wide //weight: 1
        $x_1_25 = "/hi`" wide //weight: 1
        $n_200_26 = "reg delete" ascii //weight: -200
        $n_200_27 = "netsh" ascii //weight: -200
        $n_200_28 = "msdt - Phase" ascii //weight: -200
        $n_200_29 = "Cadence License Manager" ascii //weight: -200
        $n_200_30 = "appendtool.exe -file" ascii //weight: -200
        $n_200_31 = "SXS_ASSEMBLY_NAME=Microsoft.Windows.MSDT" ascii //weight: -200
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}
