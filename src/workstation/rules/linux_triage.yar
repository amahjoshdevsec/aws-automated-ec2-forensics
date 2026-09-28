/*
  Starter YARA rules for Linux EC2 triage.
  These are intentionally simple, readable examples. In production, pull curated
  rule sets (for example your threat intel team's rules or a vetted community
  repository) into s3://<evidence-bucket>/tools/rules/ through a reviewed pipeline.
*/

rule EICAR_Test_File
{
    meta:
        description = "EICAR anti-malware test file (used by the demo target)"
        severity = "info"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii
    condition:
        $eicar and filesize < 256
}

rule Linux_CryptoMiner_Indicators
{
    meta:
        description = "Common cryptocurrency miner configuration or binary strings"
        severity = "high"
    strings:
        $s1 = "stratum+tcp://" ascii nocase
        $s2 = "stratum+ssl://" ascii nocase
        $s3 = "xmrig" ascii nocase
        $s4 = "\"donate-level\"" ascii
        $s5 = "randomx" ascii nocase
    condition:
        2 of them
}

rule Linux_Reverse_Shell_Oneliner
{
    meta:
        description = "Bash/netcat/python reverse shell one-liners"
        severity = "high"
    strings:
        $b1 = /bash -i >& ?\/dev\/tcp\/[0-9.]+\/[0-9]+/ ascii
        $b2 = /\/dev\/tcp\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{2,5}/ ascii
        $n1 = /nc(at)? (-e|-c) \/bin\/(ba)?sh/ ascii
        $p1 = "socket.socket(socket.AF_INET,socket.SOCK_STREAM)" ascii
        $p2 = "pty.spawn(\"/bin/" ascii
    condition:
        any of them
}

rule Linux_Download_And_Execute
{
    meta:
        description = "curl or wget piped straight into a shell"
        severity = "medium"
    strings:
        $c1 = /curl [^\n|]{1,200}\| ?(ba)?sh/ ascii
        $c2 = /wget [^\n|]{1,200}\| ?(ba)?sh/ ascii
        $c3 = /wget -q?O- [^\n]{1,200}\| ?(ba)?sh/ ascii
    condition:
        any of them
}

rule PHP_Webshell_Generic
{
    meta:
        description = "Generic PHP webshell patterns"
        severity = "high"
    strings:
        $a = /eval\s*\(\s*base64_decode\s*\(/ ascii nocase
        $b = /(system|shell_exec|passthru|exec)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ ascii nocase
        $c = /assert\s*\(\s*\$_(GET|POST|REQUEST)/ ascii nocase
    condition:
        any of them
}
