# PHP2Shell Scanner

Check whether the PHP on your server is affected by PHP2Shell (CVE-2026-109618 and CVE-2026-109619), two unauthenticated remote code execution flaws in the PHP engine.

**Check page:** <https://php2shell.sqzer.com/> ([Korean](https://php2shell.sqzer.com/kr/))

## Overview

PHP2Shell Scanner reads facts on the server itself, with a small PHP probe or a read-only shell script. You paste the output into the check page, which works out the verdict in your browser: **Patched**, **Vulnerable**, **Fix pending**, **Restart needed** or **Undetermined**. Each result lists its reasons and remediation commands for the setup it detected. With the PHP probe's output it also shows the interim mitigation settings in effect.

- **Advisories:** [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) (CVE-2026-109618) and [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) (CVE-2026-109619)
- **Fixed upstream in:** 8.2.35, 8.3.36, 8.4.27 and 8.5.12. PHP 8.1 and older are end of life.
- **Background:** [the write-up on sqzer.com](https://sqzer.com/writing/2026/php2shell-cve-2026-109618-cve-2026-109619/)

## How it differs from other scanners

Most PHP2Shell scanners read the version from a site's `X-Powered-By` header. That gets several common cases wrong:

| Situation | Header-based scanner | PHP2Shell Scanner |
|---|---|---|
| The version header is hidden | Cannot tell | Reads the version inside PHP |
| The distribution backported the fix (Ubuntu 22.04 keeps PHP 8.1.2; the fix is `8.1.2-1ubuntu2.28`) | Reports vulnerable | Compares with the distribution's fixed package |
| The package was updated, but PHP was not restarted | Cannot see it | Reports Restart needed (the server script checks the running processes) |
| Interim mitigations | Not checked | Reads the settings in effect (PHP probe) |
| Several sites or PHP-FPM pools | Checks one URL | Run once per site and per pool |

It never sends attack traffic or probes your site from outside, and what you paste never leaves your browser: the page has no backend, and its Content Security Policy blocks connections to any other host. Debian, Ubuntu and RHEL-family advisory data refreshes every 6 hours. Without evidence of the fix it never reports Patched: missing evidence gives Undetermined, and the result says what it could not confirm.

## What it checks

| Tool | What it reads |
|---|---|
| **PHP probe** (`php2shell-selfcheck.php`) | The PHP that serves your site: version and SAPI, OS and kernel release, web server name, core PHP packages (dpkg), the relevant settings in effect, its configuration directory, whether `open_basedir` is set, and container markers. Apart from its token and the web server name, it reads nothing from the request or the environment, and it reports no paths to your files and no application secrets. |
| **Server script** (`php2shell-server-check.sh`) | Core PHP packages (dpkg, rpm, apk) and, for dpkg and rpm, the CVE IDs in their changelogs. Web server PHP processes (PHP-FPM, Apache mod_php, CGI, LiteSpeed, FrankenPHP) still running files an update replaced. Other processes running as a common web server account (www-data, apache, nginx, nobody and similar). It also prints mitigation settings found in configuration files for you to review. |
| Server script, `--logs` | Signs of an attack: PHP memory-limit errors raised before any script ran, segmentation faults in PHP or the web server, and session files over 1 MB. |
| Server script, `--webroot DIR` | PHP files under `DIR` changed in the last 3 days, which may be web shells. |
| Check page alone | An `X-Powered-By` header (when you have no access to the server), `php -v` output or a bare version string. This is less accurate: `php -v` shows the command-line PHP, which may not be the one serving your site. |

## How to use it

1. **Collect** the facts on the server with either tool. Both can also be downloaded from the check page.
   - **PHP probe** (recommended): in [`php2shell-selfcheck.php`](check/php2shell-selfcheck.php), set `$TOKEN` to a random string of 12 or more letters, digits, `-` or `_` (for example from `openssl rand -hex 16`). Upload the file under a hard-to-guess name to the site's web root and open `https://your-site/<file>.php?k=<TOKEN>` in your browser. Repeat for each site and PHP-FPM pool.
     - Open the URL yourself before you share it anywhere. A link preview in a chat or an email would run the probe first.
     - The probe then tries to delete itself. If its output says it could not, delete it yourself.
     - A 404 means `$TOKEN` was not set or `k` does not match, or the file has already run.
     - On the RHEL family, or when `open_basedir` hides the package list, run the server script as well.
   - **Server script** (with a shell on the server). It is read-only and offline: it changes no files, restarts nothing and makes no network connections. Compare its hash with [SHA256SUMS](https://php2shell.sqzer.com/downloads/SHA256SUMS) and read it before you run it. Run it as root so it can see other accounts' processes and logs.

     ```sh
     curl -fsSLO https://php2shell.sqzer.com/downloads/php2shell-server-check.sh
     sha256sum php2shell-server-check.sh
     sudo sh php2shell-server-check.sh
     sudo sh php2shell-server-check.sh --logs --webroot /var/www   # also look for signs of compromise
     ```

2. **Paste** the whole probe output, or the `PHP2SHELL SERVERCHECK` block the script prints at the end, into the [check page](https://php2shell.sqzer.com/) and press **Run check**.
3. **Fix** your server by following the steps in the result, then run the check again until it says Patched. **Copy report** copies the result as Markdown for a ticket.

## License

[MIT](LICENSE). Copyright (c) 2026 Hyukjin An. The check page bundles the [Pretendard](https://github.com/orioncactus/pretendard) and [JetBrains Mono](https://github.com/JetBrains/JetBrainsMono) fonts under the SIL Open Font License 1.1.
