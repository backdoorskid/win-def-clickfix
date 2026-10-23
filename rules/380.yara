rule Trojan_PowerShell_Powersploit_A_2147725896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Powersploit.A!gen"
        threat_id = "2147725896"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Powersploit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:windir+'\\syswow64\\WindowsPowerShell\\v1.0\\powershell.exe'};" wide //weight: 1
        $x_1_2 = "$s=New-Object System.Diagnostics.ProcessStartInfo;$s.FileName=$b;$s.Arguments='" wide //weight: 1
        $x_1_3 = "-nop -w hidden -c " wide //weight: 1
        $x_1_4 = "New-Object IO.MemoryStream(,[Convert]::FromBase64String(''H4sIA" wide //weight: 1
        $x_1_5 = ",[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()" wide //weight: 1
        $x_1_6 = "';$s.UseShellExecute=$false;$s.RedirectStandardOutput=$true;$s.WindowStyle='Hidden';" wide //weight: 1
        $x_1_7 = "$s.CreateNoWindow=$true;$p=[System.Diagnostics.Process]::Start($s);" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}
