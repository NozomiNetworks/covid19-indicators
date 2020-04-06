// Created by Nozomi Networks Security Team

import "pe"

rule coronavirus : ransomware covid19 {

    meta:
        name = "CoronaVirus - Ransomware"
        author = "Nozomi Networks"
        date = "2020-03-30"
        description = "Detects CoronaVirus Ransomware"
        hash1 = "3299f07bc0711b3587fe8a1c6bf3ee6bcbc14cb775f64b28a61d72ebcb8968d3"
        hash2 = "a10aabde873f7965fb2e64b2ab37cc9ac0b2e601d471a305f1e7be17466864fc"
        hash3 = "705dd960f21fd4d7ceec3f46d750d29cfb6974537fdf9b541cff0c44869a1f2b"

    strings:
        $s0 = "/upload/%s_%d_%s" wide
        $s1 = "/c %s %s" wide
        $s2 = "Swvwngu"

    condition:
        uint16(0)==0x5A4D and pe.number_of_sections >= 6 and all of them
}