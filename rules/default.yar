// Starter rules for malmal's optional YARA support. They cover payloads that
// have no business in an uploaded image or document; add your own or
// community rule sets next to this file.

rule eicar_test_file
{
    meta:
        description = "EICAR antivirus test file"
    strings:
        $eicar = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule php_webshell_primitives
{
    meta:
        description = "PHP code passing request data to an execution function"
    strings:
        $call = /(eval|assert|system|passthru|shell_exec|proc_open|popen)\s*\(\s*(base64_decode\s*\(\s*)?\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        $call
}

rule shell_download_and_run
{
    meta:
        description = "Shell one-liner that downloads and executes"
    strings:
        $pipe = /(curl|wget)\s[^\n|]{1,200}\|\s*(ba)?sh/
    condition:
        $pipe
}
