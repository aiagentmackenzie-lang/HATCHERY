rule HATCHERY_Packing_UPX {
    meta:
        description = "Detects UPX-packed executables via section names and signatures"
        author = "HATCHERY"
        date = "2026-04-14"
        severity = "medium"
        mitre_attck = "T1027.002: Software Packing"

    strings:
        $s1 = "UPX0" ascii fullword
        $s2 = "UPX1" ascii fullword
        $s3 = "UPX2" ascii fullword
        $s4 = "UPX!" ascii fullword
        $sig1 = { 55 50 58 21 } // "UPX!" magic

    condition:
        any of them
}

rule HATCHERY_Packing_VMProtect {
    meta:
        description = "Detects VMProtect virtualized/protected executables"
        author = "HATCHERY"
        date = "2026-04-14"
        severity = "high"
        mitre_attck = "T1027.002: Software Packing"

    strings:
        $s1 = ".vmp0" ascii fullword
        $s2 = ".vmp1" ascii fullword
        $s3 = "VMProtect" ascii wide
        $s4 = ".vmp2" ascii fullword

    condition:
        any of them
}

rule HATCHERY_Packing_Themida {
    meta:
        description = "Detects Themida/WinLicense protected executables"
        author = "HATCHERY"
        date = "2026-04-14"
        severity = "high"
        mitre_attck = "T1027.002: Software Packing"

    strings:
        $s1 = ".themida" ascii fullword
        $s2 = ".winlice" ascii fullword
        $s3 = "Themida" ascii wide
        $s4 = "WinLicense" ascii wide

    condition:
        any of them
}

rule HATCHERY_Packing_MPRESS {
    meta:
        description = "Detects MPRESS-packed executables"
        author = "HATCHERY"
        date = "2026-04-14"
        severity = "medium"
        mitre_attck = "T1027.002: Software Packing"

    strings:
        $s1 = ".mpress1" ascii fullword
        $s2 = ".mpress2" ascii fullword
        $sig1 = { 4D 50 52 45 53 53 } // "MPRESS" magic

    condition:
        any of them
}

import "pe"

rule HATCHERY_Packing_Generic_HighEntropy {
    meta:
        description = "Detects likely packed binaries by small section count and common packer section names absent"
        author = "HATCHERY"
        date = "2026-04-14"
        severity = "low"
        mitre_attck = "T1027.002: Software Packing"

    condition:
        // PE file with very few sections — common in packed binaries
        // Legitimate PE files typically have 4+ sections (.text, .rdata, .data, .rsrc, .reloc)
        uint16(0) == 0x5A4D and
        pe.number_of_sections <= 2
}

rule HATCHERY_Packing_NSISSFX {
    meta:
        description = "Detects NSIS self-extracting archives"
        author = "HATCHERY"
        date = "2026-04-14"
        severity = "low"
        mitre_attck = "T1027.002: Software Packing"

    strings:
        $s1 = "Nullsoft.NSIS" ascii wide
        $s2 = ".ndata" ascii fullword
        $s3 = "NSIS" ascii fullword

    condition:
        2 of them
}