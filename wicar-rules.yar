rule JD_VLC_ActiveXHeapSpray
{
    meta:
        description = "Detects HTML files with JavaScript heap spraying and VLC ActiveX exploits"
        author = "JD-SRE"
        threat_type = "Exploit"
        reference = "Based on provided VLC ActiveX HTML content"
    strings:
        $html_start = "<html" ascii nocase
        $html_end = "</html" ascii nocase
        $js_tag = "<script language='javascript'" ascii nocase
        $js_unescape = "unescape" ascii
        $js_shellcode = "%u" ascii
        $js_collectgarbage = "CollectGarbage" ascii
        $js_array = "new Array(" ascii
        $js_math_atan2 = "Math.atan2" ascii
        $js_math_atan = "Math.atan" ascii
        $js_math_asin = "Math.asin" ascii
        $js_math_acos = "Math.acos" ascii
        $js_babe = "0xbabe" ascii
        $js_prototype = ".prototype." ascii
        $obj_tag = "<object" ascii nocase
        $clsid = "clsid:9BE31822-FDAD-461B-AD51-BE1D1C159921" ascii nocase
        $codebase = "http://downloads.videolan.org/pub/videolan/vlc/latest/win32/axvlc.cab" ascii
        $param_src = "<param name=\"Src\"" ascii nocase
        $hex_sequence = /%u[0-9a-fA-F]{4}/ ascii
    condition:
        $html_start at 0 and
        $html_end and
        $js_tag and
        ($js_unescape or $js_shellcode or $hex_sequence) and
        ($js_collectgarbage or $js_array or $js_math_atan2 or $js_math_atan or $js_math_asin or $js_math_acos or $js_babe or $js_prototype) and
        ($obj_tag or $clsid or $codebase or $param_src) and
        filesize < 1MB
}
 
rule JD_MS09002_MemoryCorruption
{
    meta:
        description = "Detects HTML files exploiting MS09-002 memory corruption vulnerabilities with obfuscated JavaScript"
        author = "JD-SRE"
        threat_type = "Exploit"
        reference = "Based on ms09_002_memory_corruption.html content"
    strings:
        $html_start = "<html" ascii nocase
        $html_end = "</html" ascii nocase
        $script_tag = "<script" ascii nocase
        $js_fromcharcode = "String.fromCharCode" ascii
        $js_parseint = "parseInt" ascii
        $js_hex = ",16)" ascii
        $js_eval_obfuscated = ".replace(/[A-Z]/g,\"\")" ascii
        $js_location_search = "location.search" ascii
        $js_charcodeat = "charCodeAt" ascii
        $js_xor = "^" ascii
        $hex_string = /[0-9a-fA-F]{50,}/ ascii // Long hex string (50+ chars)
        $object_tag = "<object" ascii nocase
        $js_dom = "createElement(" ascii
    condition:
        $html_start at 0 and
        $html_end and
        $script_tag and
        ($js_fromcharcode or $js_parseint or $js_hex) and
        ($js_eval_obfuscated or $js_location_search or $js_charcodeat or $js_xor or $hex_string) and
        ($object_tag or $js_dom or $js_charcodeat or $js_xor) and
        filesize < 1MB
}
 
rule JD_MS05054_Onload_Exploit
{
    meta:
        description = "Detects HTML files exploiting MS05-054 vulnerabilities with onload events and obfuscated JavaScript"
        author = "JD-SRE"
        threat_type = "Exploit"
        reference = "Based on ms05_054_onload.html content"
    strings:
        $html_start = "<html" ascii nocase
        $html_end = "</html" ascii nocase
        $script_tag = "<script" ascii nocase
        $body_onload = "<body onload=" ascii nocase
        $js_fromcharcode = "String.fromCharCode" ascii
        $js_unescape = "unescape" ascii
        $js_shellcode = "%u" ascii
        $js_prompt = "prompt(" ascii
        $js_array = "new Array(" ascii
        $js_iframe = "<iframe" ascii nocase
        $js_location_href = "document.location.href" ascii
        $obfuscated = /[\x80-\xFF]{10,}/ // Sequence of 10+ non-ASCII characters
        $hex_sequence = /%u[0-9a-fA-F]{4}/ // %u followed by 4 hex digits
    condition:
        $html_start at 0 and
        $html_end and
        $script_tag and
        $body_onload and
        ($js_fromcharcode or $js_unescape or $hex_sequence) and
        ($js_shellcode or $js_prompt or $js_array or $js_iframe or $js_location_href or $obfuscated) and
        filesize < 1MB
}
 
rule JD_Obfuscated_Html_Object
{
    meta:
        description = "Detects HTML files with obfuscated content and suspicious object tags"
        author = "JD-SRE"
        threat_type = "Malware"
        reference = "Based on obfuscated HTML file with object tag"
    strings:
        $html_start = "<html" ascii nocase
        $html_end = "</html" ascii nocase
        $object_tag = "<object" ascii nocase
        $suspicious_type = "type=\"" ascii
        $obfuscated = /[\x80-\xFF]{10,}/ // Sequence of 10+ non-ASCII characters
    condition:
        $html_start at 0 and
        $html_end and
        $object_tag and
        ($suspicious_type or $obfuscated) and
        filesize < 1MB
}
rule JD_JS_Crypto_Miner
{
    meta:
        description = "Detects specific CoinHive-based cryptocurrency mining test malware"
        author = "JD-SRE"
        threat_type = "Cryptojacking"
        reference = "Targets js_crypto_miner.html test file"
    strings:
        // More specific CoinHive patterns
        $coinhive_lib = "coinhive.com/lib/coinhive.min.js" ascii nocase
        $coinhive_anonymous = "CoinHive.Anonymous" ascii
        $coinhive_miner_start = "miner.start()" ascii
        
        // Specific to your test file - the actual site key pattern
        $test_site_key = /CoinHive\.Anonymous\(['"'][a-zA-Z0-9]{32}['"]/ ascii
        
        // Combined patterns that are very specific to mining
        $mining_throttle_combo = /throttle:\s*0\.\d+/ ascii
        $mining_mobile_check = "miner.isMobile()" ascii
        $mining_optout_check = "miner.didOptOut(" ascii
        
    condition:
        // Must be HTML file
        (uint32(0) == 0x6d74683c or uint32(0) == 0x4d54483c or // "<htm" or "<HTM"
         uint16(0) == 0x213c) and // "<!"
        
        // Must have CoinHive library reference AND Anonymous miner creation
        $coinhive_lib and ($coinhive_anonymous or $test_site_key) and
        
        // Must have miner start command
        $coinhive_miner_start and
        
        // Additional confirmation - at least one mining-specific pattern
        ($mining_throttle_combo or $mining_mobile_check or $mining_optout_check) and
        
        filesize < 1MB
}

rule JD_Java_JRE_17_Exploit
{
    meta:
        description = "Detects specific Java JRE 1.7 applet exploit test malware"
        author = "JD-SRE"
        threat_type = "Malware"
        reference = "Targets java_jre17_exec.html test file"
    strings:
        // Very specific applet patterns
        $applet_start = "<applet" ascii nocase
        $applet_end = "</applet>" ascii nocase
        
        // Specific archive and class patterns from your test file
        $java_jre17_archive = "java_jre17_exec.jar" ascii nocase
        $exploit_class = "Exploit.class" ascii nocase
        
        // Generic but suspicious applet patterns
        $archive_jar = /archive\s*=\s*['"'][^'"]*\.jar['"]/ ascii nocase
        $code_class = /code\s*=\s*['"'][^'"]*\.class['"]/ ascii nocase
        
        // Suspicious applet dimensions (very small = hidden)
        $tiny_dimensions = /width\s*=\s*['"]*[01]['"].*height\s*=\s*['"]*[01]['"]/ ascii nocase
        
    condition:
        // Must be HTML file
        (uint32(0) == 0x6d74683c or uint32(0) == 0x4d54683c or // "<htm" or "<HTM"
         uint16(0) == 0x213c) and // "<!"
        
        // Must have applet tags
        $applet_start and $applet_end and
        
        // Either match the specific test file OR have suspicious applet patterns
        (
            ($java_jre17_archive and $exploit_class) or
            ($archive_jar and $code_class and $tiny_dimensions)
        ) and
        
        filesize < 1MB
}

rule JD_Malicious_Firefox_Addon_Install
{
    meta:
        description = "Detects HTML/JavaScript files that attempt to install malicious Firefox add-ons"
        author = "JD-SRE"
        threat_type = "Malware"
        reference = "Based on firefox_proto_crmfrequest.html sample"
    strings:
        $js_addon_mgr = "AddonManager.getInstallForURL" ascii
        $js_install = "install.install()" ascii
        $mime_xpi = "application/x-xpinstall" ascii
        $url_malware = "malware.wicar.org" ascii
        $js_done_flag = "window.done" ascii
    condition:
        3 of them and
        filesize < 1MB
}

rule JD_Exploit_MS14_064_VBScript
{
    meta:
        description = "Detects VBScript using OLE and FileSystemObject to drop and execute payloads (MS14-064 style)"
        author = "JD-SRE"
        date = "2025-06-19"
        reference = "https://msrc.microsoft.com/update-guide/en-US/vulnerability/MS14-064"
        category = "exploit"

    strings:
        $s1 = "CreateObject(\"Microsoft.XMLHTTP\")" nocase
        $s2 = "GetSpecialFolder(2)" nocase
        $s3 = "scriptName = folder + \"\\HuvP.vbs\"" nocase
        $s4 = "ShellExecute \"wscript.exe\"" nocase
        $s5 = "chrw(32767)" nocase

    condition:
        3 of ($s*)
}


rule JD_Exploit_HeapSpray_JS
{
    meta:
        description = "Detects JavaScript-based heap spray exploit via shellcode and memory fill"
        author = "JD-SRE"
        date = "2025-06-19"
        category = "exploit"

    strings:
        $s1 = "var memory = new Array();" nocase
        $s2 = "function sprayHeap(" nocase
        $s3 = "retSlide = unescape(\"%u9399%ud6b2" nocase
        $s4 = "retSlide += retSlide;" nocase
        $s5 = "document.write(\"<table style=position:absolute;clip:rect(0)>" nocase

    condition:
        3 of ($s*)
}

rule JD_exploit_MS09_072_StyleObject
{
    meta:
        description = "Detects obfuscated MS09-072-style HTML exploit using style object and heap spray"
        author = "JD-SRE"
        date = "2025-06-19"
        reference = "https://msrc.microsoft.com/update-guide/en-US/vulnerability/MS09-072"

    strings:
        $s1 = "function caD()"
        $s2 = "document.getElementsByTagName('STYLE')[0].outerHTML++"
        $s3 = "unescape('%ub84e%u0c27%ub548')" nocase
        $s4 = "new Array();" nocase
        $s5 = "<BODY ONLOAD=\"mQBSPAaFaRiUEsahGiFFq()\">" nocase

    condition:
        3 of ($s*)
}

rule JD_Suspicious_Obfuscated_HTML_JS
{
    meta:
        description = "Detects obfuscated malicious HTML with JavaScript shellcode"
        author = "JD-SRE"
        date = "2025-06-19"
        severity = "high"

    strings:
        $s1 = "top.consoleRef = open" nocase
        $s2 = "unescape(String.fromCharCode" nocase
        $s3 = "window.location.reload();" nocase
        $s4 = "<body onload=window();" nocase
        $s5 = "prompt(wghit, \"\");"

    condition:
        3 of ($s*)
}
