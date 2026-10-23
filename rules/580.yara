rule Trojan_Win32_Amadey_ZA_2147942698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.ZA!MTB"
        threat_id = "2147942698"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 00 70 00 70 00 64 00 61 00 74 00 61 00 [0-60] 2e 00 74 00 6d 00 70 00 [0-16] 26 00 28 00 24 00}  //weight: 1, accuracy: Low
        $x_1_2 = "System.IO.Compression.DeflateStream([IO.MemoryStream]" wide //weight: 1
        $x_1_3 = "Convert]::FromBase64String(" wide //weight: 1
        $x_1_4 = "System.IO.Compression.CompressionMode]::Decompress" wide //weight: 1
        $x_1_5 = "New-Object IO.StreamReader($" wide //weight: 1
        $x_1_6 = "$_.ReadToEnd(" wide //weight: 1
        $x_1_7 = "System.Text.Encoding]::Ascii" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
