rule Trojan_Win32_Ceprolad_A_2147726914_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ceprolad.A"
        threat_id = "2147726914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceprolad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "112"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "certutil" wide //weight: 100
        $x_1_2 = "-urlcache" wide //weight: 1
        $x_1_3 = "/urlcache" wide //weight: 1
        $x_1_4 = " -f " wide //weight: 1
        $x_1_5 = " /f " wide //weight: 1
        $x_2_6 = "-ping" wide //weight: 2
        $x_2_7 = "/ping" wide //weight: 2
        $x_10_8 = " http" wide //weight: 10
        $n_50_9 = {6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 73 00 20 00 [0-32] 63 00 6f 00 6e 00 66 00 69 00 67 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: -50, accuracy: Low
        $n_50_10 = "http://crl.pki.va.gov/" wide //weight: -50
        $n_50_11 = "http://http.fpki.gov/" wide //weight: -50
        $n_50_12 = "https://crl.pki.va.gov/" wide //weight: -50
        $n_50_13 = "https://http.fpki.gov/" wide //weight: -50
        $n_50_14 = "http://cylanceonprem.hq" wide //weight: -50
        $n_50_15 = "http://crl.microsoft.com" wide //weight: -50
        $n_50_16 = "https://ss64.com" wide //weight: -50
        $n_50_17 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 2f 00 61 00 62 00 62 00 [0-255] 2e 00 63 00 72 00 6c 00}  //weight: -50, accuracy: Low
        $n_50_18 = {61 00 62 00 62 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 62 00 62 00 [0-255] 2e 00 63 00 72 00 6c 00}  //weight: -50, accuracy: Low
        $n_50_19 = "https://transparency.michigan.gov" wide //weight: -50
        $n_50_20 = "http://ccbdistweb.ch.intel.com" wide //weight: -50
        $n_50_21 = "https://tkccodesigningv2.vault.azure.net" wide //weight: -50
        $n_50_22 = "http://localhost/fio-62833e7bae788a6973cdf8d5.crl" wide //weight: -50
        $n_50_23 = "https://github.com/PowerShell/PowerShell/releases/download/v" wide //weight: -50
        $n_50_24 = "https://citrixaccesspiv.va.gov" wide //weight: -50
        $n_50_25 = "https://DYN-DM-biabtrix01.biab.au.ing.net" wide //weight: -50
        $n_50_26 = "https://trix.au.ing.net" wide //weight: -50
        $n_50_27 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-255] 2e 00 70 00 6f 00 77 00 65 00 72 00 62 00 69 00 2e 00 63 00 6f 00 6d 00 2f 00 68 00 6f 00 6d 00 65 00}  //weight: -50, accuracy: Low
        $n_50_28 = "http://10.254.106.53" wide //weight: -50
        $n_50_29 = "http://localhost/briarootca.crl" wide //weight: -50
        $n_50_30 = "http://localhost/BRIndustrialAutomationCodeSigningCA.crl" wide //weight: -50
        $n_50_31 = "https://www.python.org/ftp/python" wide //weight: -50
        $n_50_32 = "https://BKC-APIC-01.nseroot.com" wide //weight: -50
        $n_50_33 = "https://bootstrap.pypa.io" wide //weight: -50
        $n_50_34 = {2f 00 61 00 72 00 74 00 69 00 [0-4] 63 00 74 00 6f 00 72 00 79 00 2f 00 70 00 ?? ?? 70 00 2f 00 67 00 69 00 74 00 63 00 65 00 72 00 74 00 73 00 2f 00}  //weight: -50, accuracy: Low
        $n_50_35 = "https://ca01b-cn-06a-nx2-mgt.jpnx/certs/certs.crl" wide //weight: -50
        $n_50_36 = "https://download.windowsupdate.com" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}
