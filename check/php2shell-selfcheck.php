<?php
/*
 * php2shell-selfcheck.php
 * The PHP probe for PHP2Shell (CVE-2026-109618, CVE-2026-109619)
 *
 * Usage
 *   1. Set $TOKEN below to a random string of 12 or more characters. Use only letters,
 *      digits, '-' and '_' (A-Z a-z 0-9 - _), and keep the single quotes around it. Other
 *      characters change on the way through a URL ('+' becomes a space; '&', '#' and '%'
 *      cut or alter the value), so the probe refuses them. To make one: openssl rand -hex 16
 *   2. Give the file a name that is hard to guess as well, then upload it to the web root
 *      of the site you want to check. Save it as UTF-8 without a BOM, with nothing before
 *      the opening PHP tag.
 *   3. Open https://<site>/<file name>.php?k=<TOKEN> in a browser.
 *   4. Paste everything shown on the page into the check page.
 *
 * - It reads the PHP version, the OS and kernel release, the installed PHP package versions
 *   and a few configuration values. It sends nothing anywhere.
 * - The file deletes itself when it has run. If the output says it could not be deleted,
 *   delete it yourself.
 * - A 404 means that $TOKEN was not changed, is too short or has characters other than
 *   those above, that k is wrong, or that the file has already run and deleted itself.
 * - If you replace the file on the server, PHP may run a cached copy of the old one
 *   (OPcache). The probe clears that copy when it can and asks you to load the page again.
 *   If the new token still does not work, upload the file under a new name.
 * - It uses PHP 5.2 syntax only, so it also runs on old servers.
 */

$TOKEN = 'CHANGE_ME';
$SELF_DELETE = true;

define('P2S_TOOL_VERSION', '1.0.0');

// Before anything else: keep PHP warnings, which name file paths, out of the response.
p2s_start();

$p2s_token = p2s_token_text($TOKEN);
$p2s_given = (isset($_GET['k']) && is_string($_GET['k'])) ? trim($_GET['k']) : '';
if (!p2s_token_usable($p2s_token) || !p2s_equals($p2s_token, $p2s_given)) {
    p2s_refuse($p2s_token, $p2s_given);
}

if (P2S_EARLY_OUTPUT) {
    // Something was printed before this file started, so the headers below cannot be sent.
    $p2s_deleted = $SELF_DELETE ? p2s_delete() : false;
    p2s_respond(false, array(), 'php2shell-selfcheck ' . P2S_TOOL_VERSION . "\n"
        . "The probe stopped without collecting anything. Something was sent before it started, so it could not set its own headers. The usual cause is a byte order mark (BOM) or blank space before the opening PHP tag.\n"
        . "Save the file as UTF-8 without a BOM, with nothing before the opening PHP tag, and upload it again.\n"
        . p2s_delete_note($SELF_DELETE, $p2s_deleted));
}

$ini_names = array(
    'memory_limit',
    'post_max_size',
    'max_file_uploads',
    'max_input_vars',
    'max_input_nesting_level',
    'max_multipart_body_parts',
    'enable_post_data_reading',
    'session.upload_progress.enabled',
    'session.upload_progress.name',
    'session.auto_start',
    'fatal_error_backtraces',
    'expose_php',
);
$p2s_has_ext = function_exists('extension_loaded');

$report = array(
    'tool' => 'php2shell-selfcheck',
    'tool_version' => P2S_TOOL_VERSION,
    'schema' => 1,
    'generated_at' => function_exists('gmdate') ? @gmdate('Y-m-d\TH:i:s\Z') : '',
    'php_version' => PHP_VERSION,
    'php_extra_version' => defined('PHP_EXTRA_VERSION') ? PHP_EXTRA_VERSION : '',
    'sapi' => PHP_SAPI,
    'php_os' => PHP_OS,
    'uname_release' => p2s_kernel_release(),
    'config_path' => defined('PHP_CONFIG_FILE_PATH') ? PHP_CONFIG_FILE_PATH : '',
    'server_software' => isset($_SERVER['SERVER_SOFTWARE']) ? (string)$_SERVER['SERVER_SOFTWARE'] : '',
    'open_basedir' => p2s_open_basedir(),
    'container' => p2s_container(),
    'os_release' => p2s_os_release(),
    'dpkg_packages' => p2s_dpkg_php_packages(),
    'extensions' => array(
        'session' => $p2s_has_ext ? extension_loaded('session') : null,
        'opcache' => $p2s_has_ext ? extension_loaded('Zend OPcache') : null,
    ),
    'ini' => p2s_ini_values($ini_names),
);

$deleted = $SELF_DELETE ? p2s_delete() : false;
$report['self_deleted'] = $deleted;

p2s_respond(false, array(
        'Cache-Control: no-store, max-age=0',
        'X-Robots-Tag: noindex, nofollow',
        'X-Content-Type-Options: nosniff',
    ),
    'php2shell-selfcheck ' . P2S_TOOL_VERSION . "\n"
    . "Paste everything below into the check page. It holds the PHP version, SAPI, OS and kernel release, PHP package versions and a few settings. No paths to your site, no secrets.\n"
    . p2s_delete_note($SELF_DELETE, $deleted)
    . "\n-----BEGIN PHP2SHELL SELFCHECK-----\n"
    . p2s_json($report, 0) . "\n"
    . "-----END PHP2SHELL SELFCHECK-----\n");


// Everything below is called from above. disable_functions can remove any function, and on
// PHP 8 calling a removed function is a fatal error, so every function a host might disable
// is checked with function_exists() before it is called.

function p2s_can($names)
{
    foreach (explode(' ', $names) as $name) {
        if (!function_exists($name)) {
            return false;
        }
    }
    return true;
}

function p2s_start()
{
    // display_errors may be locked by php_admin_flag, or ini_set() disabled: then silence errors instead
    if (!function_exists('ini_set') || @ini_set('display_errors', '0') === false) {
        if (function_exists('error_reporting')) {
            @error_reporting(0);
        }
    }
    // Output before this file started (a BOM, blank space, auto_prepend_file) has already sent
    // the headers when output buffering is off. When it is on, the bytes are still in the buffer.
    $early = function_exists('headers_sent') && headers_sent();
    $level = 0;
    if (p2s_can('ob_start ob_get_level ob_get_length ob_clean ob_end_clean')) {
        if (!$early && ob_get_level() > 0 && ob_get_length() > 0) {
            @ob_clean();
        }
        // A buffer of our own catches anything printed later, so it never reaches the response
        if (@ob_start()) {
            $level = ob_get_level();
        }
    }
    define('P2S_EARLY_OUTPUT', $early);
    define('P2S_OB_LEVEL', $level);
}

// Drop whatever was printed so far, send the headers if still possible, print $body and stop.
function p2s_respond($not_found, $headers, $body)
{
    if (P2S_OB_LEVEL > 0) {
        while (ob_get_level() >= P2S_OB_LEVEL) {
            if (!@ob_end_clean()) {
                break;
            }
        }
    }
    if (p2s_can('header headers_sent') && !headers_sent()) {
        if ($not_found) {
            if (function_exists('http_response_code')) {
                http_response_code(404);
            } else {
                header('HTTP/1.0 404 Not Found');
            }
        }
        header('Content-Type: text/plain; charset=utf-8');
        foreach ($headers as $line) {
            header($line);
        }
    }
    echo $body;
    exit;
}

// A bare 404 for anyone without the token: no path, no PHP version.
function p2s_not_found()
{
    if (p2s_can('header headers_sent') && !headers_sent()) {
        if (function_exists('header_remove')) {
            @header_remove('X-Powered-By');
        } else {
            @header('X-Powered-By:');
        }
    }
    p2s_respond(true, array('Cache-Control: no-store'), "Not Found\n");
}

// The request had no usable token. If the copy of this file that ran is not the one on disk
// (OPcache with opcache.validate_timestamps=0 keeps running a replaced file), drop the cached
// copy so that the next request runs the file on disk. A visitor who holds the token of that
// newer file is told to load the page again; everyone else gets the bare 404. Nothing is
// cleared when the token on disk cannot be read: each clear wastes OPcache memory, so
// clearing on every refused request would let any visitor force OPcache restarts.
function p2s_refuse($token, $given)
{
    $disk = p2s_disk_token();
    if ($disk !== null && $disk !== $token) {
        $cleared = p2s_uncache();
        if ($disk !== null && p2s_token_usable($disk) && p2s_equals($disk, $given)) {
            p2s_respond(false, array('Cache-Control: no-store', 'X-Robots-Tag: noindex, nofollow'),
                'php2shell-selfcheck ' . P2S_TOOL_VERSION . "\n"
                . "The file on the server has changed, but PHP ran an older cached copy of it.\n"
                . ($cleared
                    ? "The cached copy has now been cleared. Load this page again. If this message comes back, upload the file under a new name.\n"
                    : "PHP did not let the probe clear the cached copy (opcache.restrict_api, or a disabled function). Upload the file under a new name.\n"));
        }
    }
    p2s_not_found();
}

// $TOKEN as a string. An unquoted number still works when it fits in an integer and has no
// leading 0; anything else counts as no token.
function p2s_token_text($token)
{
    if (is_string($token)) {
        return $token;
    }
    return is_int($token) ? (string)$token : '';
}

// 12 or more of A-Z a-z 0-9 - _, the characters that pass through a URL unchanged.
function p2s_token_usable($token)
{
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    return is_string($token) && $token !== 'CHANGE_ME' && strlen($token) >= 12
        && strspn($token, $chars) === strlen($token);
}

function p2s_equals($known, $given)
{
    if (function_exists('hash_equals')) {
        return hash_equals($known, $given);
    }
    if (strlen($known) !== strlen($given)) {
        return false;
    }
    $diff = 0;
    for ($i = 0; $i < strlen($known); $i++) {
        $diff |= ord($known[$i]) ^ ord($given[$i]);
    }
    return $diff === 0;
}

// The token written in this file on disk now (quoted, or an unquoted number), or null when
// the file cannot be read, the token line is not found or its number is not one PHP keeps as written.
function p2s_disk_token()
{
    $code = p2s_read(__FILE__);
    if (!is_string($code) || !function_exists('preg_match')) {
        return null;
    }
    if (preg_match('/^\s*\$TOKEN\s*=\s*(?:([\'"])([^\'"]*)\1|([0-9]+))\s*;/m', $code, $m)) {
        if (!isset($m[3]) || $m[3] === '') {
            return $m[2];
        }
        // An unquoted number counts only when PHP compiles it to the same digits. With a leading 0
        // it is octal, and when it is too large for an integer it is a float, which is no token.
        return (string)(int)$m[3] === $m[3] ? $m[3] : null;
    }
    return null;
}

// The contents of a file, or false.
function p2s_read($path)
{
    if (function_exists('file_get_contents')) {
        return @file_get_contents($path);
    }
    if (!p2s_can('fopen fread fclose')) {
        return false;
    }
    $fh = @fopen($path, 'rb');
    if (!$fh) {
        return false;
    }
    $data = '';
    while (strlen($data) < 1048576) {
        $chunk = @fread($fh, 8192);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $data .= $chunk;
    }
    fclose($fh);
    return $data;
}

// Remove this file from the opcode cache, so that the next request compiles the file on disk.
// Returns false when nothing was cleared: no opcode cache, the file was not cached, or the cache refused.
function p2s_uncache()
{
    $cleared = false;
    if (function_exists('opcache_invalidate') && @opcache_invalidate(__FILE__, true)) {
        $cleared = true;
    }
    // APC, the opcode cache of PHP 5.2 to 5.4
    if (function_exists('apc_delete_file') && @apc_delete_file(__FILE__)) {
        $cleared = true;
    }
    return $cleared;
}

function p2s_delete()
{
    // Clear the cached copy first: on PHP 7.4 and older, opcache_invalidate() fails once the
    // file is gone, and a stale copy would then answer a new upload under the same name.
    p2s_uncache();
    return function_exists('unlink') && @unlink(__FILE__);
}

function p2s_delete_note($self_delete, $deleted)
{
    if (!$self_delete) {
        return "Warning: self-delete is turned off. Delete this file when you have finished.\n";
    }
    if ($deleted) {
        return "This probe has been deleted from the server.\n";
    }
    return 'Warning: this probe could not be deleted. Delete it from the server yourself: ' . basename(__FILE__) . "\n";
}

// The values of the given settings, with null for a setting this PHP does not have. null
// instead of the list when neither ini_get() nor ini_get_all() can be called.
function p2s_ini_values($names)
{
    $out = array();
    if (function_exists('ini_get')) {
        foreach ($names as $name) {
            $value = @ini_get($name);
            $out[$name] = ($value === false || $value === null) ? null : (string)$value;
        }
        return $out;
    }
    if (function_exists('ini_get_all')) {
        $all = @ini_get_all();
        if (is_array($all)) {
            foreach ($names as $name) {
                if (!isset($all[$name]) || !is_array($all[$name])) {
                    $out[$name] = null;
                } else {
                    // ini_get() returns '' where ini_get_all() has null
                    $out[$name] = isset($all[$name]['local_value']) ? (string)$all[$name]['local_value'] : '';
                }
            }
            return $out;
        }
    }
    return null;
}

// Whether open_basedir limits the paths PHP may open. Only the yes or no is reported, not the paths.
function p2s_open_basedir()
{
    $ini = p2s_ini_values(array('open_basedir'));
    if ($ini !== null) {
        return is_string($ini['open_basedir']) && $ini['open_basedir'] !== '';
    }
    // The settings cannot be read
    return p2s_root_visible() === false;
}

// Whether PHP may look at the root directory: it always exists, so only open_basedir hides it.
// null when neither is_dir() nor file_exists() can be called.
function p2s_root_visible()
{
    if (function_exists('is_dir')) {
        return @is_dir('/');
    }
    if (function_exists('file_exists')) {
        return @file_exists('/');
    }
    return null;
}

// The kernel release, as uname -r prints it, or '' when it cannot be read.
function p2s_kernel_release()
{
    if (function_exists('php_uname')) {
        $release = @php_uname('r');
        if (is_string($release) && $release !== '') {
            return $release;
        }
    }
    $release = p2s_read('/proc/sys/kernel/osrelease');
    if (is_string($release)) {
        $release = trim($release);
        if ($release !== '' && strlen($release) <= 200) {
            return $release;
        }
    }
    return '';
}

// true when a container marker exists, null when the probe cannot look for one (open_basedir
// hides the root directory), false otherwise.
function p2s_container()
{
    if (!function_exists('file_exists')) {
        return null;
    }
    if (@file_exists('/.dockerenv') || @file_exists('/run/.containerenv')) {
        return true;
    }
    return p2s_root_visible() === true ? false : null;
}

// Fields of /etc/os-release, or of the legacy release files. null when none could be read,
// usually because open_basedir blocks /etc (see open_basedir in the report).
function p2s_os_release()
{
    if (!function_exists('preg_match')) {
        return null;
    }
    foreach (array('/etc/os-release', '/usr/lib/os-release') as $file) {
        $content = p2s_read($file);
        if (!is_string($content) || $content === '') {
            continue;
        }
        $out = array();
        foreach (explode("\n", $content) as $line) {
            if (preg_match('/^(ID|ID_LIKE|VERSION_ID|VERSION_CODENAME|PRETTY_NAME)=(.*)$/', trim($line), $m)) {
                $out[$m[1]] = trim($m[2], "\"'");
            }
        }
        if (count($out) > 0) {
            return $out;
        }
    }
    // Older distributions without os-release
    $out = array();
    foreach (array('/etc/redhat-release', '/etc/debian_version') as $file) {
        $content = p2s_read($file);
        if (is_string($content) && $content !== '') {
            $out['LEGACY_' . strtoupper(basename($file))] = trim($content);
        }
    }
    return count($out) > 0 ? $out : null;
}

// Exact distribution versions of the installed PHP packages (used to check for backports).
// null if the package list cannot be read (open_basedir, or not a dpkg system).
function p2s_dpkg_php_packages()
{
    if (!p2s_can('fopen fgets fclose preg_match')) {
        return null;
    }
    $fh = @fopen('/var/lib/dpkg/status', 'r');
    if (!$fh) {
        return null;
    }
    $found = array();
    $cur = array();
    while (true) {
        $line = @fgets($fh);
        if ($line === false || trim($line) === '') {
            if (isset($cur['Package'], $cur['Version'], $cur['Status'])
                && preg_match('/ ok installed$/', $cur['Status'])
                && preg_match('/^(libapache2-mod-php[0-9.]+|php[0-9.]+-(common|fpm|cli|cgi))$/', $cur['Package'])
                && count($found) < 40) {
                $found[] = array(
                    'name' => $cur['Package'],
                    'version' => $cur['Version'],
                    'source' => isset($cur['Source']) ? $cur['Source'] : '',
                );
            }
            $cur = array();
            if ($line === false) {
                break;
            }
            continue;
        }
        if (preg_match('/^(Package|Status|Version|Source): (.*)$/', rtrim($line, "\r\n"), $m)) {
            $cur[$m[1]] = $m[2];
        }
    }
    fclose($fh);
    return $found;
}

function p2s_json($value, $depth)
{
    if (is_null($value)) {
        return 'null';
    }
    if (is_bool($value)) {
        return $value ? 'true' : 'false';
    }
    if (is_int($value) || is_float($value)) {
        return (string)$value;
    }
    if (is_array($value)) {
        if (count($value) === 0) {
            return '[]';
        }
        $pad = str_repeat('  ', $depth + 1);
        $items = array();
        $is_list = array_keys($value) === range(0, count($value) - 1);
        foreach ($value as $k => $v) {
            $items[] = $pad . ($is_list ? '' : p2s_json_string((string)$k) . ': ') . p2s_json($v, $depth + 1);
        }
        $close = str_repeat('  ', $depth);
        return ($is_list ? '[' : '{') . "\n" . implode(",\n", $items) . "\n" . $close . ($is_list ? ']' : '}');
    }
    return p2s_json_string((string)$value);
}

function p2s_json_string($s)
{
    $out = '"';
    $len = strlen($s);
    for ($i = 0; $i < $len; $i++) {
        $c = $s[$i];
        $o = ord($c);
        if ($c === '"') {
            $out .= '\\"';
        } elseif ($c === '\\') {
            $out .= '\\\\';
        } elseif ($o < 0x20 || $o === 0x7f) {
            $out .= sprintf('\\u%04x', $o);
        } else {
            $out .= $c;
        }
    }
    return $out . '"';
}
