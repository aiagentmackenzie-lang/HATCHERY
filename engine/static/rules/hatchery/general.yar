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
        $b64 = /[A-Za-z0-9+\/]{80,}={0,2}/

    condition:
        #b64 > 3
}

rule HATCHERY_Suspicious_HexStrings {
    meta:
        description = "Detects suspicious hex-encoded strings often used in shellcode or config encoding"
        author = "HATCHERY"
        date = "2026-04-14"
        severity = "low"

    strings:
        $hex1 = { 4D 5A }  // MZ header inside non-PE file (embedded PE)
        $hex2 = { 50 4B 03 04 }  // ZIP/PK header (embedded archive)

    condition:
        any of them
}