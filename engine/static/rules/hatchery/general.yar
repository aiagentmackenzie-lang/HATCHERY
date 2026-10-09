rule HATCHERY_EICAR_TestFile {
    meta:
        description = "EICAR standard anti-virus test file — not malware, used for AV testing"
        author = "HATCHERY"
        date = "2026-04-14"
        severity = "info"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"

    strings:
        $s1 = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii

    condition:
        $s1
}

rule HATCHERY_Suspicious_Base64_EncodedPayload {
    meta:
        description = "Detects long base64-encoded strings that may hide payloads"
        author = "HATCHERY"
        date = "2026-04-14"
        severity = "medium"
        mitre_attck = "T1027: Obfuscated Files or Information"

    strings:
        // Upper bound the quantifier: an unbounded {80,} against a short
        // alphabet is a quadratic scan on large files, which YARA-X flags.
        $b64 = /[A-Za-z0-9+\/]{80,512}={0,2}/

    condition:
        #b64 > 3
}

rule HATCHERY_Suspicious_HexStrings {
    meta:
        description = "Detects suspicious hex-encoded strings often used in shellcode or config encoding"
        author = "HATCHERY"
        date = "2026-04-14"
        severity = "low"
        mitre_attck = "T1027: Obfuscated Files or Information"

    strings:
        $mz = "MZ" ascii        // embedded PE header inside a non-PE file
        $pk = { 50 4B 03 04 }   // embedded ZIP/archive header

    condition:
        any of them
}