rule Trojan_Win32_Reverseshell_ZH_2147979969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reverseshell.ZH!MTB"
        threat_id = "2147979969"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reverseshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Net.Sockets.TcpClient" wide //weight: 1
        $x_1_2 = "IO.StreamReader($" wide //weight: 1
        $x_1_3 = "]::UserName" wide //weight: 1
        $x_1_4 = "]::MachineName" wide //weight: 1
        $x_1_5 = "Invoke-Expression $" wide //weight: 1
        $x_1_6 = ".ConnectAsync(" wide //weight: 1
        $x_1_7 = "Environment" wide //weight: 1
        $n_50_8 = "127.0.0.1" wide //weight: -50
        $n_50_9 = "localhost" wide //weight: -50
        $n_50_10 = "0.0.0.0" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}
