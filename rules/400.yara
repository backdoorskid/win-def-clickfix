rule Trojan_PowerShell_SuspLoadExec_Z_2147972904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/SuspLoadExec.Z!MTB"
        threat_id = "2147972904"
        type = "Trojan"
        platform = "PowerShell: "
        family = "SuspLoadExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[IO.Compression.CompressionMode]::Decompress);$" wide //weight: 1
        $x_1_2 = "[Convert]::FromBase64String($" wide //weight: 1
        $x_1_3 = "New-Object IO.MemoryStream(,$" wide //weight: 1
        $x_1_4 = "IO.Compression.GZipStream($" wide //weight: 1
        $x_1_5 = "[Reflection.Assembly]::Load($" wide //weight: 1
        $x_1_6 = ".ToArray())|Out-Null;" wide //weight: 1
        $x_1_7 = ".CopyTo($" wide //weight: 1
        $x_1_8 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
