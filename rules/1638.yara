rule Trojan_Win32_SuspLoad_BK_2147980392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLoad.BK!MTB"
        threat_id = "2147980392"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "New-Object IO.MemoryStream(,$" wide //weight: 1
        $x_1_2 = "; Invoke-Expression $" wide //weight: 1
        $x_1_3 = "System.Security.Cryptography.AesManaged; $" wide //weight: 1
        $x_1_4 = ".CryptoStream($" wide //weight: 1
        $x_1_5 = ".CryptoStreamMode]::Read); $" wide //weight: 1
        $x_1_6 = "[Convert]::FromBase64String(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
