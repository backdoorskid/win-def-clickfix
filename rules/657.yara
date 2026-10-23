rule Trojan_Win32_Cerobgar_A_2147813239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cerobgar.A"
        threat_id = "2147813239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerobgar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "mSIexeC" wide //weight: 100
        $x_1_2 = "0dz.me:8080" wide //weight: 1
        $x_1_3 = "euya.cn:8080" wide //weight: 1
        $x_1_4 = "glnj.nl:8080" wide //weight: 1
        $x_1_5 = "gz3.nl:8080" wide //weight: 1
        $x_1_6 = "j68.info:8080" wide //weight: 1
        $x_1_7 = "j8.si:8080" wide //weight: 1
        $x_1_8 = "jjl.one:8080" wide //weight: 1
        $x_1_9 = "k5m.co:8080" wide //weight: 1
        $x_1_10 = "kglo.link:8080" wide //weight: 1
        $x_1_11 = "kjaj.top:8080" wide //weight: 1
        $x_1_12 = "lwip.re:8080" wide //weight: 1
        $x_1_13 = "mirw.wf:8080" wide //weight: 1
        $x_1_14 = "nzm.one:8080" wide //weight: 1
        $x_1_15 = "pjz.one:8080" wide //weight: 1
        $x_1_16 = "q2.rs:8080" wide //weight: 1
        $x_1_17 = "qmpo.art:8080" wide //weight: 1
        $x_1_18 = "r4e.pl:8080" wide //weight: 1
        $x_1_19 = "skqv.eu:8080" wide //weight: 1
        $x_1_20 = "u0.pm:8080" wide //weight: 1
        $x_1_21 = "uoej.net:8080" wide //weight: 1
        $x_1_22 = "w6.nz:8080" wide //weight: 1
        $x_1_23 = "xjam.hk:8080" wide //weight: 1
        $x_1_24 = "yuiw.xyz:8080" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}
