# PHP2Shell Scanner

PHP2Shell Scanner tells you whether the PHP on your server is affected by PHP2Shell (CVE-2026-109618 and CVE-2026-109619), two unauthenticated remote code execution flaws in the PHP engine. It collects facts on the server itself, with a PHP probe and a POSIX shell script, and a static page computes the verdict entirely in your browser. It understands distribution backports, notices when PHP was patched but not restarted, and reports interim mitigations.

- **Check page:** <https://sqzer-x.github.io/php2shell-scanner/> (Korean: <https://sqzer-x.github.io/php2shell-scanner/kr/>)
- **Advisories:** [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) (CVE-2026-109618, memory corruption during out-of-memory handling) and [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) (CVE-2026-109619, use-after-free of global state)
- **Fixed upstream in:** 8.2.35, 8.3.36, 8.4.27, 8.5.12

## Why it exists

Remote scanners that read the PHP version from a response header get several common cases wrong.

| Situation | Version-header scanner | PHP2Shell Scanner |
|---|---|---|
| The server hides its version header | Cannot tell | Reads the version from inside PHP |
| The distribution backported the fix (Ubuntu 22.04 ships PHP 8.1.2; the fix is in `8.1.2-1ubuntu2.28`) | Reports vulnerable, or "no fix available" | Compares with the distribution's fixed version: **Patched** |
| The package was updated but PHP was not restarted | Cannot see the installed package | Compares running and installed versions: **Restart needed** |
| Interim mitigations | Unknown | Reads the effective settings |
| Several vhosts or PHP-FPM pools | Checks one URL | Run once per vhost and per pool |

The name says scanner, but it never sends attack traffic and never probes your site from outside. It reads facts from inside the server.

## What is in the repository

| Path | What it is |
|---|---|
| [`check/php2shell-selfcheck.php`](check/php2shell-selfcheck.php) | The PHP probe. Upload it to a web root and open it once in a browser. |
| [`site/`](site/) | The check page, in English and Korean ([`site/kr/`](site/kr/)). A static site deployed to GitHub Pages. The verdict logic is in [`site/lib/`](site/lib/); its English and Korean text is in [`site/lib/messages.js`](site/lib/messages.js), the page chrome strings in [`site/i18n.js`](site/i18n.js). The data it judges with is in [`site/data/`](site/data/), and the fonts it bundles in [`site/fonts/`](site/fonts/). |
| [`tools/update-distro-data.mjs`](tools/update-distro-data.mjs), [`.github/workflows/pages.yml`](.github/workflows/pages.yml) | The data pipeline. Refreshes distribution security data and deploys the site. |
| [`tools/build-site.mjs`](tools/build-site.mjs), [`tools/serve.mjs`](tools/serve.mjs) | Assemble the deployable site into `_site/`, and serve it locally for a preview. |
| [`scripts/php2shell-server-check.sh`](scripts/php2shell-server-check.sh) | The server script. Package changelogs, restart status and signs of compromise. |
| [`test/`](test/), [`.github/workflows/ci.yml`](.github/workflows/ci.yml) | Tests for the verdict logic, ShellCheck for the server script, and PHP lint across versions. |

The deployed site also serves both server-side files under `downloads/`, with a `SHA256SUMS` file.

## How to use it

### The PHP probe (most accurate)

1. In [`php2shell-selfcheck.php`](check/php2shell-selfcheck.php), set `$TOKEN` to a random string of 12 or more letters, digits, `-` or `_`, for example the output of `openssl rand -hex 16`. Keep the single quotes around it, and save the file as UTF-8 without a BOM.
2. Rename the file to something hard to guess and upload it to the web root of the site you want to check.
3. Open `https://your-site/<file>.php?k=<TOKEN>` in a browser.
4. Copy the whole output and paste it into the check page.

- The file deletes itself after it runs (`$SELF_DELETE`). If it cannot, the output says so. Delete it by hand.
- A 404 means the file has already run and deleted itself, `$TOKEN` was not changed, `$TOKEN` is shorter than 12 characters or has other characters than those above, or `k` is wrong. Do not paste the URL into a chat or an email before you have opened it yourself: a link preview would run the probe, receive its output and leave you a 404. Upload a fresh copy to run it again.
- Run it once per site (vhost) and once per PHP-FPM pool. Each can use a different PHP.
- It uses PHP 5.2 syntax only, so it runs on old servers. Tested on PHP 5.6 to 8.5.

| It reads | It never reads |
|---|---|
| PHP version and SAPI | Environment variables |
| OS name and version (`/etc/os-release`, or the legacy release files) and the kernel release | Web root or script paths |
| Installed PHP package versions (`/var/lib/dpkg/status`, PHP packages only) | Request headers, cookies or form data |
| 12 relevant `php.ini` settings, and whether the session and OPcache extensions are loaded | Passwords, keys or application configuration |
| PHP configuration directory, web server name (`SERVER_SOFTWARE`), container markers, whether `open_basedir` is set | Full `phpinfo()` output |

If `open_basedir` blocks `/var/lib/dpkg/status`, the check page warns that the backport verdict may be inaccurate. Run the server script as well.

### The server script (when you have a shell)

```sh
sudo sh php2shell-server-check.sh
sudo sh php2shell-server-check.sh --logs --webroot /var/www
```

| Option | What it checks |
|---|---|
| (always) | Installed PHP packages (dpkg, rpm, apk) and CVE entries in their changelogs. PHP processes still using files replaced by an update (`(deleted)` in `/proc`). Config files that set mitigation settings. Other processes running as the web server account. |
| `--logs` | Web server and PHP-FPM error logs, including rotated ones, for out-of-memory errors before any script ran (`in Unknown on line 0`) and crashes. Kernel log segfaults in PHP or Apache. Session files over 1 MB. |
| `--webroot DIR` | PHP files (`.php`, `.phtml`, `.phar`) under `DIR` changed in the last 3 days, to spot web shells. Repeat for several directories. |
| `-h`, `--help` | Prints the usage and exits. |

- It is read-only and offline. It changes no files, restarts nothing and makes no network connections.
- Run it as root to see other accounts' processes and logs. Without root it names the logs and directories it could not read, and a count it could not complete is given as `unknown` instead of 0.
- Paste the `PHP2SHELL SERVERCHECK` block at the end into the check page. The block holds OS release fields, package names and versions, process names and counts only. No log lines and no file paths. Review the readable report above it on the server.

### The check page

Paste the probe output, the server script output, or both into the same box, and press **Run check** (or Ctrl+Enter). Without access to the server you can paste an `X-Powered-By` header (for example from `curl -I`), `php -v` output or a bare version string, but accuracy is lower. A header shows only the PHP that served that one URL, and `php -v` shows the command-line PHP, which can differ from the one serving your site. If your distribution is not detected, pick it in the **Distribution** list. To see what a result looks like first, load one of the examples above the box.

The result shows the verdict and its reasons, the evidence it rests on (versions, distribution, SAPI and how exposed that SAPI is), the required actions, any signs of compromise the server script found, the state of interim mitigations, and your distribution's advisories.

**Required actions** is step-by-step remediation for the setup the check detected. It names the version running now and the fixed release or package to move to (your distribution's package for your release, the upstream release, or an official Docker image tag), gives copyable commands built from what the check saw (the installed package names, the package manager, the service or container that runs PHP), and ends with how to confirm the fix, usually by running the probe or the server script again until the result says Patched. When the result is Undetermined, the first steps say what to collect to settle it. **Copy report** copies the whole result as Markdown, for a ticket or a change request.

## Verdicts

| Label | Title | Meaning |
|---|---|---|
| Patched | This PHP has the fix | At or above the upstream fixed version, or a distribution package with both fixes backported. |
| Vulnerable | This PHP is vulnerable | Below the fixed version. Includes upstream builds of end-of-life (EOL) branches, 8.1 and older. |
| Fix pending | Vulnerable, and your distribution has no fix yet | Your distribution tracks the CVEs for this package but has not released a fixed version. |
| Restart needed | Fixed on disk, still vulnerable in memory | The fixed package is installed, but the running PHP is the old one. |
| Undetermined | Not enough to decide | The evidence is missing or incomplete. |

When evidence is missing, the verdict is Undetermined. The check page never reports a server as safe without evidence.

## How verdicts are decided

The verdict logic is in [`site/lib/judge.js`](site/lib/judge.js). It first settles which PHP it is judging. With the probe output, a header, `-v` output or a version string, that is the running PHP (`PHP_VERSION`). With server script output, it is also every installed PHP build: one per Debian source package, rpm collection or apk prefix, so `php8.2` and `php8.4` installed side by side are judged separately. The installed build that the probe's PHP was judged with is not judged a second time. A paste that holds several separate outputs is judged output by output: two probe outputs, two server script outputs, a probe output and a header, every PHP version in the `X-Powered-By` and `Server` headers of a `curl -IL` redirect chain (also several in one merged header line, such as `PleskLin, PHP/8.2.20`), several `-v` lines, or several bare version lines. Server script output from another system than the probe's is one of those outputs too (see point 11). The same output pasted twice counts once. The worst verdict is reported, with one line per build or output. A server script block whose BEGIN line was not copied is read from its first data line up to its END line.

1. **Pre-releases and newer branches.** `alpha`, `beta`, `RC`, `pre` and `-dev` builds (`8.5.12-dev` is the snapshot before 8.5.12, and Alpine writes `8.5.12_rc1`) are Undetermined, and so is any Debian version with a `~` suffix before the release (`8.4.27~git20261001-1` is a snapshot taken before 8.4.27). Branches newer than the fixed-release table are Undetermined as well.
2. **Upstream fixed releases.** A version at or above the fixed release for its branch (8.2.35, 8.3.36, 8.4.27, 8.5.12) is Patched, unless the package of that PHP on disk is older and does not have the fix (point 4).
3. **Builds that are not distribution packages** are judged against the upstream releases:
   - deb.sury.org builds, recognised in `PHP_VERSION` or in the installed package. A sury version string never selects an Ubuntu or Debian release. For end-of-life branches (7.4, 8.0, 8.1), deb.sury.org ships backported fixes under the same upstream version (the `8.1.34-9` changelog has "Backported from 8.2.35"), so there the changelog of exactly the installed build, read by the server script, decides: both CVEs recorded is Patched, a changelog read without them is Vulnerable, and a changelog that was not read is Undetermined. A Debian build dated before the fixed releases (`+0~20250101`) cannot have them and is Vulnerable.
   - Remi builds on the RHEL family (`.remi` release tag, `phpNN-php-*` packages, or configuration under `/etc/opt/remi/`). Remi's collections of end-of-life branches (php74, php80, php81) carry backports under the same version number, so they follow the same changelog rule as deb.sury.org's: Patched when every package records both fixes, Vulnerable when the changelog was read without them, Undetermined when it was not read.
   - A PHP whose configuration directory is outside `/etc`: the official Docker images use `/usr/local/etc/php`, and control panels and self-built PHP use their own prefix. Installed packages are not used for it.
   - A build whose upstream version is newer than the package the distribution release ships (for example `8.3.20` on Ubuntu 24.04, which ships 8.3.6). An installed package of an older upstream version than a running PHP that is below the fix is ignored, because it is not what runs.
   - On the RHEL family, a PHP when the server script output lists no PHP installed with rpm.
   - Alpine, with a note to check Alpine's advisories, and other distributions, with a note that they may backport fixes without changing the version. SUSE (SLES, openSUSE Leap) does backport into its own PHP packages, so a version below the fix there is Undetermined, and the page asks for its advisories or the package changelog.

   Below the fixed release is Vulnerable. An end-of-life branch (8.1 and older) is Vulnerable, and for 7.4, 8.0 and 8.1 the page points to the minimal backport branches in php-src, but offers a source build only for a PHP that is not a package. Versions older than 5.4 are Undetermined.
4. **Debian and Ubuntu.** The release comes from os-release, from the parent of a derivative (Linux Mint, LMDE, Pop!_OS, Raspbian) by codename, from the Distribution list, or from a version string. An inferred release must agree with the version: `~deb12u1` and `ubuntu0.24.04` name one, in `PHP_VERSION` or in the installed package of the same branch. Otherwise it is the one Ubuntu release that ships exactly that upstream version. An interim release such as 22.10 (`8.1.7-1ubuntu3.6`) is not mapped onto 22.04 and stays Undetermined. The version compared is `PHP_VERSION` when it carries a distribution revision, otherwise the installed package of the same branch. It is compared with the release's fixed version using dpkg ordering ([`site/lib/version.js`](site/lib/version.js), tested against `dpkg --compare-versions` results), ignoring the epoch and repack markers such as `+dfsg`. When the fixed version keeps the upstream version (a backport), only a revision the distribution builds itself counts: one with `ubuntu` on Ubuntu, one with `debNNuN` on Debian. A PPA's `8.3.6-1+ppa1` or a Debian-style `8.1.2-2` sorts above Ubuntu's fixed version but is not its backport, so it is Undetermined. If the fix ships only through Ubuntu Pro (ESM), the page says so. Three more checks apply when the running PHP is the package's:
   - **Downgrades.** An installed package of the running SAPI (`php8.2-fpm`, `libapache2-mod-php8.2`) that is older than the running PHP and does not have the fix is Vulnerable, also when `PHP_VERSION` is an upstream fixed release (8.2.35 running, 8.2.32 on disk, configuration in `/etc/php/8.2/fpm`): the next restart loads it, and for PHP-FPM so does a reload. The steps reinstall the fixed package before any restart or reload, and say not to restart the processes that still run the fixed build.
   - **The SAPI's own package.** Debian and Ubuntu build the PHP engine into the binary of each SAPI, so the package of the SAPI that runs must be in the list: `php8.3-common` does not vouch for a `php-fpm8.3` whose `php8.3-fpm` is missing (dpkg lists only fully installed packages, and an interrupted update leaves it half-installed). That is Undetermined, with the commands that show and finish the interrupted update.
   - **The revision in `PHP_VERSION`.** On Ubuntu 22.04 and older, the security updates report their revision (`8.1.2-1ubuntu2.28`), and only the release's original build reports the plain version. A plain `8.1.2` next to an updated package is that original build, loaded before the update: Restart needed.
5. **Same version before and after the fix.** Ubuntu 24.04 and later report the plain upstream version (`8.3.6`) both before and after the fix. Without a package list or a revision, a version equal to the release's packaged upstream version is Undetermined, and the page asks for the server script or a probe that can read `/var/lib/dpkg/status`. A lower version is Vulnerable. When the distribution is not known at all, a version could be a distribution package with the fixes backported under the same number. Such a version is Undetermined as well. That covers a version a Debian or Ubuntu release ships (`8.3.6`, `8.1.2`), a version a Red Hat advisory names (`8.0.30` on RHEL 9), and any version below the fix of a branch that a RHEL module stream has fixed (7.4 on RHEL 8, 8.2 on RHEL 8 and 9, 8.3 on RHEL 9): a module stream keeps the upstream version it started with, which the data does not give. A `Server` header that names a RHEL rebuild (`Apache/2.4.57 (Rocky Linux)`) selects the RHEL family.
6. **Distribution list.** A choice in the Distribution list is used unless the pasted output contradicts it. That is the case when os-release or a RHEL kernel names another distribution or release, when the version string carries another distribution's revision or names another release, or when Upstream build is chosen for a `PHP_VERSION` with a distribution revision. The detected distribution is then used, and a note says so.
7. **RHEL family** (RHEL, CentOS, Rocky Linux, AlmaLinux, Oracle Linux, CloudLinux, EuroLinux, Amazon Linux). The family is also recognised from an `.elN` kernel release in the probe output when os-release cannot be read, but not inside a container, which reports the host's kernel. Red Hat backports fixes without changing the upstream version number. The evidence is therefore the CVE entries in the changelog of the rpm package of the PHP being judged: the one with the same upstream version, narrowed by the probe's configuration path when several match. A changelog counts only for the version it was read from, and a changelog from another PHP package on the same server never counts. A CVE that Red Hat lists as Not affected for that release counts as covered, but only for that branch: a module stream's branch, or the branch of Red Hat's own `php` package for the plain `php` state (5.3 on RHEL 6, 5.4 on RHEL 7, and the branch the advisories name for later releases). All CVEs fixed or not affected means Patched. A changelog read without a fix is Vulnerable when the build is older than the exact build a Red Hat advisory names for that branch and release (`php-0:8.0.30-8.el9_8.1`, `php8.4-0:8.4.27-1.el10_2`, compared as rpm does), and on Amazon Linux, which ships its PHP fixes as upstream releases, when it is below the upstream fix. Anything else, including a module stream build (its advisory names no package version) and a running PHP that matches no installed rpm package, is Undetermined. When the fix is a new upstream release (a Red Hat rebase, or Amazon Linux), the changelog entry names the version rather than the CVEs, so the steps confirm the update by its version.
8. **Changelog fallback.** On Debian and Ubuntu, the distribution data may have no entry for the release or package, or the release cannot be identified. Then an installed package that already has the upstream fix, next to an older `PHP_VERSION`, is Restart needed. Otherwise, both CVEs in the changelog of exactly the package build being judged, at the version the server script read, count as Patched.
9. **Restart detection.** The fix is on disk but not in memory (Restart needed) in two cases: the installed package has the fix and the running version is older, or a PHP process that can run the PHP being judged maps a file marked `(deleted)` in `/proc`. When the running version itself shows the fix and the stale processes are of the same SAPI and branch as the probe, with no current process of the same name, the verdict stays Patched, with a note that a newer package is waiting for a restart. One PHP-FPM master and its workers are all stale or all current, so a stale `php-fpm` next to a current one is another PHP, and that gives Restart needed, as do stale processes of another SAPI. Stale processes over a build that does not have the fix are not called a missed restart: the files may have been replaced by a downgrade, and the steps install the fixed package first. A process counts for a build only when that build's packaging can run it. Debian, Ubuntu and Alpine name FPM after the branch (`php-fpm8.2`, `php-fpm83`; `php5-fpm` on Ubuntu 14.04), and the process belongs to the build only when the build has that SAPI's package. Apache on Debian and Ubuntu runs PHP only through a `libapache2-mod-php` package. On the RHEL family every collection runs as `php-fpm` (from `php-fpm` or `php8.4-fpm`) or in `httpd` (from `php`, `mod_php` or Amazon Linux 2023's `php8.4-modphp`). A PHP process that none of the checked builds can run means a PHP that was not checked: an unversioned `php-fpm` on Debian or Ubuntu (usually a container), `apache2` with PHP loaded but no `libapache2-mod-php` package, or a `php-fpm8.3` with no `php8.3-fpm` package. Such a process turns Patched into Undetermined, or into Restart needed when it maps deleted files. `-v` output of `php-fpm` or `php-cgi` shows the binary on disk rather than the running service, so a Patched result from it says that a restart is not confirmed.
10. **Patched on the installed package alone.** A Patched verdict can rest on the installed package rather than on the running version string: with server script output alone, or with a probe whose `PHP_VERSION` has no revision. The reasons then say that the loaded build was not confirmed, or that no running process of that build was found. The verdict is Undetermined instead when the server script ran without root and the build runs PHP as a service (FPM, CGI or an Apache module): with `hidepid`, other accounts' processes are hidden without a trace, so the processes it saw are not all that run. It is Undetermined as well when the build's service is one the current server script cannot see in `/proc` (`php5-fpm` and `php5-cgi` on Ubuntu 14.04 and Debian 8, Apache with Alpine's `mod_php83.so`) and no process of it is listed.
11. **Mixing outputs.** Server script output is combined with probe output only when both describe the same system at the same moment. Its packages, changelogs and processes are not used for the probe's PHP in these cases, and its signs of compromise are kept:
    - Both report an OS release and they differ. The server script names any system without os-release `rhel` with its major version, which matches the probe's CentOS, CloudLinux or Oracle Linux of the same release.
    - The probe ran in a container, and its own OS release and dpkg package list do not match the server script's. The script may have run on the host. On the RHEL family the probe cannot list rpm packages, so this is always the case there.
    - `open_basedir` kept the probe from seeing whether it runs in a container, and its dpkg package list does not tie the two outputs together.
    - The probe's dpkg package list differs from the server script's, for example one taken before an update and one after.

    In the first three cases the server script output describes another system, or may: it is judged as an output of its own, and the worst result is reported. In the last case which output is current is unknown, so the result is never Patched, even when the probe's `PHP_VERSION` shows the fix, and the page asks for both outputs taken together.
12. **Missing evidence.** If `open_basedir` keeps the probe from reading os-release and the package list, a version below the upstream fix is Undetermined. The exceptions are a configuration directory that shows a build that is not a distribution package, and a distribution picked from the list. The kernel release can still identify the RHEL family, which then follows the RHEL rules. Server script output that is incomplete never gives Patched: a block without its END line, a block that starts below its first line, PHP processes the script could not read or whose status line was cut off (also next to a probe whose `PHP_VERSION` shows the fix, which vouches only for its own PHP), and a paste that was cut because it was longer than two million characters or held more than 64 outputs. When the script ran as root and still could not read some processes, which happens inside a container without `CAP_SYS_PTRACE`, the page says to run it on the host or use the probe, not to run it again with sudo.
13. **Interim mitigations** (`memory_limit=-1`, `session.upload_progress.enabled=0` and others) are shown for reference and never change a verdict. Without the probe's settings, the actions name the advisory's mitigations. Once PHP is patched they are not recommended, and the page suggests reverting `memory_limit=-1`. The advisory still suggests keeping session upload progress off if you do not use it. After a downgrade the mitigation is not offered, because the reload that applies it would load the vulnerable build; when PHP-FPM processes still use replaced files, the mitigation step says so.
14. **Signs of compromise.** A count the server script could not read (`unknown`), or a run without root, is never reported as "nothing suspicious". The page says which sources were not checked.
15. **Untrusted input.** Every pasted value is text: a setting, an OS release field or a package name of another type (an object, a list) is left out, and a SAPI or OS name is never looked up as a member of a JavaScript object. A paste of several megabytes is read in time proportional to its size.

## Privacy and safety

- The check page's Content Security Policy blocks every connection except to the site itself, and the page uses that only to load its own data, configuration and checksum files. What you paste never leaves your browser. No analytics, no third-party scripts or fonts.
- Nothing sends attack requests. The probe reads versions, packages and settings. The server script also reads package changelogs, the process list with command lines, the files each PHP process has mapped and PHP and web server configuration files. With `--logs` and `--webroot` it also reads logs, session file sizes and the names and dates of PHP files. Its terminal output can show command lines and log lines; the check page needs only the block between the BEGIN and END lines.
- The probe refuses to run without a token of 12 or more letters, digits, `-` or `_`, and deletes itself after running. Where PHP allows it, it first clears its own OPcache entry, and it also clears a cached copy that no longer matches the file on disk, so a new upload under the same name runs the new code. If PHP does not allow that (`opcache.restrict_api`), upload the new copy under a new name. It sends `noindex` and `no-store` headers.

## Data sources and refresh

| File | Contents | Refresh |
|---|---|---|
| [`site/data/upstream.json`](site/data/upstream.json) | Upstream fixed versions, CVE details, EOL backport branches | Maintained by hand. Every data run cross-checks it against the php-src advisories. A mismatch fails the run and nothing is deployed. |
| [`site/data/distro.json`](site/data/distro.json) | Debian and Ubuntu fixed versions per package, RHEL advisories and package states | Every 6 hours, and on every push to `main`. Deployed straight away; committed to `main` after the deploy, and only when it changes. |
| `site/data/status.json` | Last check time, success per source, whether `upstream.json` matches the advisories | Written on every data run, so on every deploy. Not committed (listed in `.gitignore`). |

Sources: the php-src advisories above, [OSV](https://osv.dev/) for Debian and Ubuntu, and the [Red Hat Security Data API](https://access.redhat.com/hydra/rest/securitydata/).

If one source fails, its previous data is kept and the check page lists the failed source. If the advisory lookup itself fails, the cross-check is skipped for that run and recorded as a failed source. If every source fails, the run fails.

A 404 from OSV or Red Hat normally means the distribution has published nothing for that CVE yet, and it is recorded as no data. If `distro.json` already holds entries for that CVE, the 404 is treated as a fault at the source instead: the previous entries are kept, the source is listed as failed, and `status.json` names the CVE under `kept_previous`. If a record really was withdrawn, delete its entries from `distro.json` by hand.

Each run builds and deploys exactly the commit it checked out, after its tests pass, with the freshly fetched data. A separate job then commits the new `distro.json` to the latest `main`. If that push is rejected, because `main` moved on or a rule blocks pushes from workflows, the run shows a warning, the deployed site is still current, and the next run tries again.

## Self-hosting on GitHub Pages

1. Create an empty repository on GitHub. Do not push yet.
2. In **Settings > Pages > Build and deployment > Source**, choose **GitHub Actions**. Do this first: the deploy workflow cannot turn Pages on, so a run before this step fails at `configure-pages`.
3. Push this repository to `main`. [`pages.yml`](.github/workflows/pages.yml) runs the tests, refreshes the data, deploys, and then commits `distro.json` if it changed. After that it refreshes the data every 6 hours. If you pushed before step 2, run it by hand: **Actions > Deploy site > Run workflow**.
4. To use your own domain, enter it in **Settings > Pages > Custom domain** and add a DNS record:
   - Subdomain: a `CNAME` record pointing to `<user>.github.io`.
   - Apex domain: four `A` records, `185.199.108.153`, `185.199.109.153`, `185.199.110.153` and `185.199.111.153`.

   Turn on **Enforce HTTPS** once the certificate is issued. Verify the domain in your account settings (**Settings > Pages**) so nobody else can take it over.
5. On public repositories, scheduled workflows pause after 60 days without activity. If that happens, re-enable the workflow in the **Actions** tab.

The page points at your copy without edits. The download commands on the page and in the results use the address the page is served from, and the GitHub links and the footer of a copied report use the repository the workflow runs in, which [`tools/build-site.mjs`](tools/build-site.mjs) writes to `config.json`. The report link in the header, the author link in the footer and the README link shown when JavaScript is off are plain links in [`site/index.html`](site/index.html) and [`site/kr/index.html`](site/kr/index.html); change them there if you want.

The data commit is pushed to `main` with the workflow's own `GITHUB_TOKEN`. If a ruleset or branch protection on `main` blocks that push, for example by requiring pull requests, the site still deploys with fresh data, but every data change ends with a warning and the committed `distro.json` falls behind the deployed one. To keep the history in git, allow GitHub Actions to push to `main`.

## Local development

You need Node.js 20 or later. There are no dependencies to install.

```sh
npm test              # tests for verdicts, remediation steps, translations and version comparison (node --test)
npm run update-data   # fetch distribution data into site/data/ (distro.json, and status.json, which git ignores)
npm run build         # assemble the deployable site into _site/
npm run serve         # build, then serve _site/ at http://127.0.0.1:8790
```

`npm test` runs `node --test` with no arguments, so Node.js finds `test/*.test.mjs` with its default patterns on every supported version. CI runs it on Node.js 20, 22 and 24, and the deploy workflow runs the same command before it deploys.

`npm run update-data` uses `GITHUB_TOKEN` from the environment if set, which avoids GitHub API rate limits. [`tools/build-site.mjs`](tools/build-site.mjs) copies `site/`, adds both server-side files under `downloads/` with a `SHA256SUMS` file, and writes `config.json`. The deploy workflow runs the same script, so a local preview matches production.

[`tools/serve.mjs`](tools/serve.mjs) is a small static file server with no dependencies. It listens on `127.0.0.1` only, serves `_site/` and nothing outside it, and sends `.php` and `.sh` files as plain text. Set `PORT` to use a port other than 8790.

## Limitations

- Verdicts rest on versions, packages and settings. Nothing tests whether an attack actually succeeds.
- Distribution data covers Debian, Ubuntu and the RHEL family only. Alpine and other distributions are judged by upstream version. SUSE, which backports fixes without changing the version, is Undetermined below the fix; another distribution that does the same can be reported Vulnerable when it is patched, so check its advisories.
- On the RHEL family a Red Hat package is reported Vulnerable only when its changelog was read without the fix and it is older than the exact build a Red Hat advisory names, or, on Amazon Linux, older than the upstream fix. A module stream build without changelog evidence stays Undetermined, because the module advisories name no package version. Self-built PHP and control panel PHP with a configuration directory outside `/etc` (CloudLinux alt-php, cPanel ea-php, Plesk) are judged by upstream version, so a vendor backport into an end-of-life branch is not recognised there.
- deb.sury.org and Remi builds of end-of-life branches can carry backports under the same version, which only their changelog shows. Without the server script's changelog reading they are Undetermined; deb.sury.org's Ubuntu builds carry no build date, so even an old one cannot be told from a new one by its version.
- When the distribution is not known (a bare header or version string), a version below the fix of a branch that a RHEL 8 or 9 module stream has fixed (7.4, 8.2, 8.3) is Undetermined, because those streams keep their old upstream version. A version string of the last release of another end-of-life branch, such as `8.1.34`, can be a deb.sury.org build with backported fixes and is still reported Vulnerable by its upstream version; the PHP probe or the server script settles it.
- A probe that ran in a container is combined with server script output only when its own OS release and dpkg package list match the script's, and so is a probe that `open_basedir` keeps from seeing whether it runs in one. On the RHEL family the probe cannot list rpm packages, so run the server script inside the container (`docker exec`) and paste its output on its own.
- A build from a php-src backport branch cannot be recognised by its version number and is reported as Vulnerable.
- On Ubuntu 24.04 and later the probe cannot see a missed restart, because `PHP_VERSION` stays the same when the fix is installed. The server script's process check, run as root, can. On Ubuntu 22.04 and older the updated builds report their revision, so a plain version next to an updated package is reported as Restart needed; this rests on the builds observed for these releases.
- Restart detection through `/proc` needs root to see processes owned by other accounts. A verdict that rests on the installed package is Undetermined when the server script reports PHP processes it could not read, or ran without root while the build runs PHP as a service. The current server script does not list `php5-fpm`, `php5-cgi` or Apache with Alpine's `mod_php83.so`, so those builds stay Undetermined until it does.
- dpkg lists only fully installed packages, so a SAPI package that an interrupted update left half-installed is missing from both outputs, and the result is Undetermined rather than a verdict about that package.
- With server script output, every installed PHP build counts toward the worst verdict, also when probe output is pasted with it, including a build that no site uses.
- The check page sees only what you paste. Other sites and FPM pools on the same server need their own check.
- The signs-of-compromise checks are heuristics. Finding nothing does not mean nothing happened.
- Check the upstream advisories and your distribution's security notices as well.

## License

[MIT](LICENSE). Copyright (c) 2026 Hyukjin An.

The check page bundles two fonts under the SIL Open Font License 1.1, both served from the site itself: [Pretendard](https://github.com/orioncactus/pretendard) ([licence](site/fonts/OFL-Pretendard.txt)) for text, the variable font split into Unicode-range subsets ([`site/fonts/pretendard.css`](site/fonts/pretendard.css)) so a page loads only the glyphs it shows, and [JetBrains Mono](https://github.com/JetBrains/JetBrainsMono) ([licence](site/fonts/OFL-JetBrainsMono.txt)) for code, in regular and bold.
