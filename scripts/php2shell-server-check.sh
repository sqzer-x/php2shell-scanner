#!/bin/sh
# php2shell-server-check.sh
# The server script for PHP2Shell (CVE-2026-109618, CVE-2026-109619)
#
# - Read-only. It changes no files, restarts no services and makes no network connections.
# - Run it as root so it can also check processes and logs owned by other accounts (www-data etc.).
# - Paste the "PHP2SHELL SERVERCHECK" block at the end into the check page.
#
# Usage: sh php2shell-server-check.sh [--logs] [--webroot DIR]...
#   --logs         Search web server and PHP logs, the kernel log and session files for signs of an attack.
#   --webroot DIR  List PHP files under DIR changed in the last 3 days (to spot web shells). Can be repeated.

set -u

TOOL_VERSION=1.0.0
CVES="CVE-2026-109618 CVE-2026-109619"
DO_LOGS=0
WEBROOTS=""

while [ $# -gt 0 ]; do
  case "$1" in
    --logs) DO_LOGS=1 ;;
    --webroot)
      shift
      if [ $# -eq 0 ]; then echo "--webroot needs a directory." >&2; exit 2; fi
      WEBROOTS="$WEBROOTS
$1"
      ;;
    -h|--help) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

NL='
'
MACHINE=""
add() { MACHINE="$MACHINE$1$NL"; }
# Machine lines are '|'-delimited, so replace any '|' and line breaks inside values.
clean() { printf '%s' "$1" | tr '|\r\n' '/  '; }
section() { printf '\n== %s ==\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }
# File names, log lines and command lines can be chosen by an attacker. Replace control characters (C0, DEL and
# UTF-8 encoded C1) before printing them, so that escape sequences cannot change what the terminal shows.
C1_RE=$(printf '\302[\200-\237]')
safe() { tr '\t' ' ' | LC_ALL=C sed "s/[[:cntrl:]]/?/g; s/$C1_RE/?/g"; }
# A count in the result block is 0 only when every source behind it was read. When a source could not be read,
# a count above 0 is still given (it is then a lower bound), and a 0 becomes "unknown".
count_or_unknown() { if [ "$1" -gt 0 ] || [ "$2" = 0 ]; then printf '%s' "$1"; else printf 'unknown'; fi; }

IS_ROOT=0
if [ "$(id -u 2>/dev/null)" = "0" ]; then IS_ROOT=1; fi

add "tool|php2shell-server-check|$TOOL_VERSION"
add "env|root|$IS_ROOT"

echo "php2shell-server-check $TOOL_VERSION"
echo "Read-only check. Nothing is changed."
if [ "$IS_ROOT" = 0 ]; then
  echo "Note: not running as root, so processes owned by other accounts and some logs may not be checked. Counts that could not be checked are given as unknown."
fi

# ---------------------------------------------------------------- Operating system
section "Operating system"
OS_FILE=""
for f in /etc/os-release /usr/lib/os-release; do
  if [ -r "$f" ]; then OS_FILE=$f; break; fi
done
if [ -n "$OS_FILE" ]; then
  for key in ID ID_LIKE VERSION_ID VERSION_CODENAME PRETTY_NAME; do
    val=$(sed -n "s/^$key=//p" "$OS_FILE" | head -n 1 | sed "s/^[\"']//; s/[\"']\$//")
    if [ -n "$val" ]; then add "os|$key|$(clean "$val")"; fi
    if [ "$key" = PRETTY_NAME ] && [ -n "$val" ]; then echo "$val"; fi
  done
elif [ -r /etc/redhat-release ]; then
  rel=$(cat /etc/redhat-release)
  echo "$rel"
  add "os|ID|rhel"
  major=$(printf '%s' "$rel" | sed -n 's/.*release \([0-9][0-9]*\).*/\1/p')
  if [ -n "$major" ]; then add "os|VERSION_ID|$major"; fi
else
  echo "No operating system information found."
fi

# ---------------------------------------------------------------- Packages
section "Installed PHP packages"
PKG_LINES=""
if have dpkg-query; then
  PKG_LINES=$(dpkg-query -W -f='${Status}|${Package}|${Version}|${Source}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null |
    awk -F'|' '$1 ~ / installed$/ && $2 ~ /^(libapache2-mod-php[0-9.]+|php[0-9.]+-(common|fpm|cli|cgi))$/ {
      src = $4; sub(/ .*/, "", src); print "pkg|dpkg|" $2 "|" $3 "|" src }')
fi
if have rpm; then
  # php-common: RHEL family and Fedora. php8.4-common: RHEL 10 and Amazon Linux 2023 (php8.4-modphp is the Apache
  # module there). php82-php-common: Remi's collections. Extensions, PEAR and PECL packages are left out.
  RPM_LINES=$(rpm -qa --qf '%{NAME}|%{EPOCH}:%{VERSION}-%{RELEASE}\n' 2>/dev/null | sed 's/|(none):/|/' |
    awk -F'|' '$1 ~ /^(php|php-(common|fpm|cli|cgi)|php[0-9]+\.[0-9]+(-(common|fpm|cli|cgi|modphp))?|php[0-9]+-php-(common|fpm|cli)|mod_php)$/ {
      print "pkg|rpm|" $1 "|" $2 "|" }')
  if [ -n "$RPM_LINES" ]; then PKG_LINES="$PKG_LINES
$RPM_LINES"; fi
fi
if have apk; then
  APK_LINES=$(apk info -v 2>/dev/null | grep -E '^php[0-9]*(-(common|fpm|cgi|apache2))?-[0-9]' |
    sed -E 's/^(.*)-([0-9][^-]*-r[0-9]+)$/pkg|apk|\1|\2|/')
  if [ -n "$APK_LINES" ]; then PKG_LINES="$PKG_LINES
$APK_LINES"; fi
fi
PKG_LINES=$(printf '%s\n' "$PKG_LINES" | sed '/^$/d')
if [ -n "$PKG_LINES" ]; then
  printf '%s\n' "$PKG_LINES" | awk -F'|' '{ printf "  %-28s %s (%s)\n", $3, $4, $2 }'
  add "$PKG_LINES"
else
  echo "No PHP installed through a package manager was found. It may have been built from source or come from a container image."
fi

# Does the package changelog record the CVE fixes? (On RHEL-family systems this is the most reliable evidence.)
# The changelog of every matched dpkg and rpm package is read, so that the check page can use the one that belongs
# to the PHP that actually runs. A package whose changelog cannot be read gets no changelog line.
section "CVE entries in package changelogs"
cve_counts() {  # $1 = package, $2 = version, $3 = changelog text
  echo "  $1 $2"
  for c in $CVES; do
    n=$(printf '%s\n' "$3" | grep -cF "$c")
    echo "    $c: found on $n line(s)"
    add "changelog|$(clean "$1")|$c|$n"
  done
}
CL_PKGS=$(printf '%s\n' "$PKG_LINES" | awk -F'|' '($2 == "rpm" || $2 == "dpkg") && !seen[$2 "|" $3]++ { print $2 "|" $3 "|" $4 }')
set -f
for entry in $CL_PKGS; do
  mgr=${entry%%|*}; rest=${entry#*|}; p=${rest%%|*}; v=${rest#*|}
  if [ "$mgr" = rpm ]; then
    if text=$(rpm -q --changelog "$p" 2>/dev/null); then
      cve_counts "$p" "$v" "$text"
    else
      echo "  $p $v: the changelog could not be read."
    fi
  else
    log=""
    for f in "/usr/share/doc/$p/changelog.Debian.gz" "/usr/share/doc/$p/changelog.gz"; do
      if [ -r "$f" ]; then log=$f; break; fi
    done
    if [ -n "$log" ]; then
      cve_counts "$p" "$v" "$(gzip -dc "$log" 2>/dev/null)"
    else
      echo "  $p $v: no changelog installed (minimal and container images often leave out /usr/share/doc)."
    fi
  fi
done
set +f
if [ -z "$CL_PKGS" ]; then echo "  No changelogs to check."; fi

# ---------------------------------------------------------------- Restart status
# A process that was not restarted after an update replaced its files shows them as "(deleted)" in /proc.
section "Processes running PHP"
if [ -d /proc/self ]; then
  PROC_LINES=""
  UNREAD_LIST=""
  READ_COMMS=""
  for d in /proc/[0-9]*; do
    comm=$(cat "$d/comm" 2>/dev/null) || continue
    case "$comm" in
      php-fpm*|php5-fpm*|apache2|httpd|frankenphp|lsphp*|php-cgi*|php5-cgi*) ;;
      *) continue ;;
    esac
    comm=$(clean "$comm")
    # Another account's maps file is readable only as root (inside a container, with CAP_SYS_PTRACE).
    maps=$(cat "$d/maps" 2>/dev/null)
    if [ -z "$maps" ]; then
      UNREAD_LIST="$UNREAD_LIST$comm$NL"
      continue
    fi
    # Remembered even when it turns out to be out of scope, so that unreadable processes of the same name
    # (the workers of an Apache without mod_php) are not reported as PHP processes that could not be checked.
    READ_COMMS="$READ_COMMS$comm$NL"
    status=ok
    case "$comm" in
      apache2|httpd)
        # Apache without mod_php (a proxy, or in front of PHP-FPM) is out of scope. For Apache only the PHP
        # module and extensions count: an apache2-bin or httpd update alone leaves no old PHP code in memory.
        printf '%s\n' "$maps" | grep -Eq 'libphp|mod_php' || continue ;;
      *)
        exe=$(readlink "$d/exe" 2>/dev/null)
        case "$exe" in *" (deleted)") status=stale ;; esac ;;
    esac
    if printf '%s\n' "$maps" | grep -Eq '(libphp|php[^ ]*\.so|/php/).* \(deleted\)$'; then status=stale; fi
    PROC_LINES="$PROC_LINES$comm|$status$NL"
  done
  if [ -n "$PROC_LINES" ]; then
    SUMMARY=$(printf '%s' "$PROC_LINES" | sort | uniq -c |
      awk '{ n = $1; sub(/^[ \t]*[0-9]+[ \t]/, ""); split($0, a, "|"); print "proc|" a[1] "|" n "|" a[2] }')
    printf '%s\n' "$SUMMARY" | safe | awk -F'|' '{ s = ($4 == "stale") ? "using pre-update files, restart needed" : "using current files"; printf "  %-14s %3s process(es): %s\n", $2, $3, s }'
    add "$SUMMARY"
  else
    echo "  No web server processes running PHP were found."
  fi
  # Child processes inherit the memory of their parent (master) process, so if at least one
  # process with the same name was read, the ones that could not be read do not count.
  if [ -n "$UNREAD_LIST" ]; then
    MISSING=$(printf '%s' "$UNREAD_LIST" | sort | uniq -c | while read -r cnt c; do
      printf '%s' "$READ_COMMS" | grep -qxF "$c" || echo "$cnt"
    done | awk '{ s += $1 } END { print s + 0 }')
    SKIPPED=$(printf '%s' "$UNREAD_LIST" | grep -c .)
    if [ "$MISSING" -gt 0 ]; then
      if [ "$IS_ROOT" = 1 ]; then
        echo "  ${MISSING} process(es) could not be checked, even as root. Inside a container, reading another account's"
        echo "  process memory map needs CAP_SYS_PTRACE: run the script on the host, or use the PHP probe."
      else
        echo "  ${MISSING} process(es) could not be checked for lack of permission (run again as root)"
      fi
      add "proc|unreadable|$MISSING|unknown"
    else
      echo "  (Skipped ${SKIPPED} process(es) that could not be read; a process with the same name was checked instead.)"
    fi
  fi
  if [ "$IS_ROOT" = 0 ] && ! cat /proc/1/comm >/dev/null 2>&1; then
    echo "  /proc hides other accounts' processes from this account (hidepid), so PHP processes may be missing here. Run again as root."
  fi
else
  echo "  Could not check: /proc is not available."
fi

# ---------------------------------------------------------------- Configuration files
section "Configuration files with interim mitigation settings"
CONF_HITS=""
for d in /etc/php /etc/php.ini /etc/php.d /etc/php-fpm.conf /etc/php-fpm.d /etc/php[0-9]* /etc/opt/remi \
  /usr/local/etc/php /usr/local/etc/php-fpm.conf /usr/local/etc/php-fpm.d \
  /opt/cpanel/ea-php*/root/etc /opt/plesk/php/*/etc /opt/alt/php*/etc /usr/local/lsws/lsphp*/etc \
  /etc/apache2 /etc/httpd; do
  [ -e "$d" ] || continue
  # The setting name must stand alone: "max_memory_limit" or a commented-out line does not count.
  # Templates and package manager leftovers (php.ini-production, *.default, *.rpmnew, *.dpkg-dist ...) are never loaded.
  hits=$(grep -rIsnHE '^[[:space:]]*([^;#[:space:]][^;#]*[^a-z_.;#])?(memory_limit|session\.upload_progress\.enabled|session\.auto_start|fatal_error_backtraces|max_input_nesting_level)([^a-z_]|$)' "$d" 2>/dev/null |
    grep -vE '^[^:]*\.(ini-development|ini-production|default|dist|rpmnew|rpmsave|dpkg-dist|dpkg-old|dpkg-new|ucf-dist|ucf-old):[0-9]+:')
  if [ -n "$hits" ]; then CONF_HITS="$CONF_HITS$hits$NL"; fi
done
if [ -n "$CONF_HITS" ]; then
  printf '%s' "$CONF_HITS" | head -n 60 | safe | sed 's/^/  /'
  echo "  (Each file applies to different targets. Use the PHP probe to see the values actually in effect.)"
else
  echo "  None found in the usual configuration directories. The defaults may be in effect, or the settings are made"
  echo "  elsewhere (a hosting panel, .user.ini, a pool file in another place). The PHP probe shows the values in effect."
fi

# ---------------------------------------------------------------- Web server account processes
section "Other processes running as the web server account"
# A process counts as the web server only when its executable is a known server binary in a system directory,
# owned by root. Names and arguments alone are not trusted: a miner started as "/tmp/.x/httpd" or with
# "php-fpm" in its arguments must still be listed.
server_name() {
  case "$1" in php-fpm*|php5-fpm*|php-cgi*|php5-cgi*|lsphp*|apache2|httpd|httpd.*|nginx|frankenphp|lighttpd) return 0 ;; esac
  return 1
}
system_path() {
  case "$1" in /usr/*|/bin/*|/sbin/*|/opt/*) return 0 ;; esac
  return 1
}
# A genuine PHP binary that runs a script named on its command line (php-cgi -f x.php, frankenphp php-cli x.php)
# is not serving web requests. $1 = binary name, $2 = arguments.
runs_script() {
  case "$1" in php-cgi*|php5-cgi*|lsphp*|frankenphp) ;; *) return 1 ;; esac
  case " $2 " in
    *" -f "*|*" -r "*|*" -a "*|*" php-cli "*|*".php "*|*".phar "*|*".phtml "*|*".inc "*) return 0 ;;
  esac
  return 1
}
WEBUSER=unknown
if ! have ps; then
  echo "  Could not check: ps is not installed."
else
  PS_OUT=$(ps -eo user=,pid=,ppid=,args= 2>/dev/null)
  OTHERS=$(printf '%s\n' "$PS_OUT" | awk -v me="$(id -un 2>/dev/null)" 'NF && $1 != me { n++ } END { print n + 0 }')
  if [ -z "$PS_OUT" ]; then
    echo "  Could not check: ps listed no processes."
  elif [ "$IS_ROOT" = 0 ] && [ "$OTHERS" = 0 ]; then
    echo "  Could not check: other accounts' processes are hidden from this account (hidepid). Run again as root."
  else
    # Leave out this script, the processes it starts and the shells it was started from.
    CANDIDATES=$(printf '%s\n' "$PS_OUT" | awk -v self="$$" '
      NF >= 3 { n++; u[n] = $1; p[n] = $2; pp[$2] = $3; a = $0
        sub(/^[ \t]*[^ \t]+[ \t]+[^ \t]+[ \t]+[^ \t]+[ \t]*/, "", a); args[n] = a }
      END {
        x = self
        while (x != "" && !(x in skip)) { skip[x] = 1; x = pp[x] }
        mine[self] = 1
        do { c = 0; for (i = 1; i <= n; i++) if (!(p[i] in mine) && (pp[p[i]] in mine)) { mine[p[i]] = 1; c = 1 } } while (c)
        for (i = 1; i <= n; i++)
          if (!(p[i] in skip) && !(p[i] in mine) && u[i] ~ /^(www-data|apache|nginx|http|wwwrun|nobody|lighttpd)$/)
            print u[i], p[i], args[i]
      }')
    RES=$(printf '%s\n' "$CANDIDATES" | while read -r user pid args; do
      [ -n "$pid" ] || continue
      # busybox ps puts "{name} " in front of the arguments when the first argument is not the process name.
      cmd=$args
      # Patterns inside $(...) carry a leading "(": bash before 4.4 otherwise ends the substitution at ")".
      case "$cmd" in ("{"*"} "*) cmd=${cmd#*"} "} ;; esac
      exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
      if [ -n "$exe" ]; then
        path=${exe% (deleted)}
        if server_name "${path##*/}" && system_path "$path" && ! runs_script "${path##*/}" "$cmd" &&
          [ -n "$(find -H "/proc/$pid/exe" -prune -user 0 2>/dev/null)" ]; then
          continue
        fi
      else
        # The executable of another account's process is readable only as root (in a container, with
        # CAP_SYS_PTRACE). Fall back to the kernel's process name and the first argument.
        comm=$(cat "/proc/$pid/comm" 2>/dev/null)
        argv0=${cmd%% *}
        by_name=0
        if server_name "$comm" && ! runs_script "$comm" "$cmd"; then
          case "$argv0" in
            (/*) if system_path "$argv0" && server_name "${argv0##*/}"; then by_name=1; fi ;;
            (*/*) ;;
            (*) by_name=1 ;;
          esac
        fi
        if [ "$by_name" = 1 ]; then echo N; continue; fi
        exe="(not readable)"
      fi
      printf 'O %s %s exe=%s args=%s\n' "$user" "$pid" "$exe" "$args"
    done)
    ODD=$(printf '%s\n' "$RES" | sed -n 's/^O //p')
    WEBUSER=$(printf '%s\n' "$ODD" | grep -c .)
    BY_NAME=$(printf '%s\n' "$RES" | grep -c '^N$')
    if [ "$WEBUSER" -gt 0 ]; then
      printf '%s\n' "$ODD" | head -n 20 | safe | cut -c1-240 | sed 's/^/  /'
      if [ "$WEBUSER" -gt 20 ]; then echo "  ... and $((WEBUSER - 20)) more"; fi
      echo "  Check what these processes are. If a shell, download tool or coin miner is running as the web server account, suspect a compromise."
    else
      echo "  None"
    fi
    if [ "$BY_NAME" -gt 0 ]; then
      echo "  (${BY_NAME} web server process(es) were accepted by name only, because their executable could not be read."
      echo "  Run as root on the host to check the executables too.)"
    fi
  fi
fi
add "webuser_proc|$WEBUSER"

# ---------------------------------------------------------------- Logs (--logs)
LOGS_READ=0
LOGS_UNREAD=0
LOG_DIRS_SEEN=$NL
OOM_TOTAL=0
CRASH_TOTAL=0
# Succeeds when the files in directory $1 should be read: it exists, is readable and was not read under another name.
log_dir() {
  [ -d "$1" ] || return 1
  if [ ! -r "$1" ] || [ ! -x "$1" ]; then
    echo "  $1: directory not readable"
    LOGS_UNREAD=$((LOGS_UNREAD + 1))
    return 1
  fi
  real=$(cd "$1" 2>/dev/null && pwd -P) || return 1
  case "$LOG_DIRS_SEEN" in *"$NL$real$NL"*) return 1 ;; esac
  LOG_DIRS_SEEN="$LOG_DIRS_SEEN$real$NL"
  return 0
}
# Prints "<memory exhaustion count> <crash count>", then the last two matching lines.
log_counts() {
  LC_ALL=C awk '
    /exhausted.*in Unknown on line 0/ { o++; hit = 1 }
    /SIGSEGV|signal 11|Segmentation fault/ { c++; hit = 1 }
    hit { last1 = last2; last2 = $0; hit = 0 }
    END { print o + 0, c + 0; if (last1 != "") print last1; if (last2 != "") print last2 }'
}
scan_log() {
  [ -f "$1" ] || return 0
  case "$1" in
    *.gz) reader=gzip ;;
    *.xz) reader=xz ;;
    *.bz2) reader=bzip2 ;;
    *.zst) reader=zstd ;;
    *) reader="cat" ;;
  esac
  res=""
  if [ -r "$1" ] && have "$reader"; then
    if [ "$reader" = cat ]; then
      res=$(log_counts 2>/dev/null <"$1")
    else
      res=$("$reader" -dc 2>/dev/null <"$1" | log_counts)
    fi
  fi
  if [ -z "$res" ]; then
    printf '  %s: not readable\n' "$1" | safe
    LOGS_UNREAD=$((LOGS_UNREAD + 1))
    return 0
  fi
  LOGS_READ=$((LOGS_READ + 1))
  counts=$(printf '%s\n' "$res" | head -n 1)
  oom=${counts% *}
  crash=${counts#* }
  if [ "$oom" -gt 0 ] || [ "$crash" -gt 0 ]; then
    printf '  %s: %s memory exhaustion error(s) before the script ran, %s crash(es)\n' "$1" "$oom" "$crash" | safe
    printf '%s\n' "$res" | sed '1d' | safe | cut -c1-300 | sed 's/^/      /'
  fi
  OOM_TOTAL=$((OOM_TOTAL + oom))
  CRASH_TOTAL=$((CRASH_TOTAL + crash))
}

if [ "$DO_LOGS" = 1 ]; then
  section "Suspicious log entries"
  # Web server error logs, including per-site and TLS logs (ssl_error_log, example.com-error.log) and panel paths.
  for d in /var/log/apache2 /var/log/httpd /var/log/nginx /var/log/lighttpd /usr/local/apache/logs /etc/apache2/logs \
    /usr/local/apache2/logs /usr/local/lsws/logs /var/www/vhosts/system/*/logs; do
    if log_dir "$d"; then
      for f in "$d"/*error*; do scan_log "$f"; done
    fi
  done
  # PHP and PHP-FPM logs: /var/log/php-fpm/, /var/log/php83/ (Alpine), panel PHP-FPM directories, /var/log/php8.2-fpm.log.
  for d in /var/log/php* /var/log/plesk-php* /opt/cpanel/ea-php*/root/usr/var/log/php-fpm; do
    if log_dir "$d"; then
      for f in "$d"/*log*; do scan_log "$f"; done
    fi
  done
  for f in /var/log/php*.log*; do scan_log "$f"; done
  if [ "$LOGS_READ" = 0 ]; then
    echo "  No web server or PHP log file could be read in the usual places. Logs may go to the journal, to a"
    echo "  hosting panel's own directory or, in a container, to stderr."
  fi
  FILES_INCOMPLETE=0
  if [ "$LOGS_READ" = 0 ] || [ "$LOGS_UNREAD" -gt 0 ]; then FILES_INCOMPLETE=1; fi

  KERNEL_READ=0
  KCOUNT=0
  if KLOG=$(dmesg 2>/dev/null); then
    KERNEL_READ=1
  elif have journalctl && KLOG=$(journalctl -k -q --no-pager 2>/dev/null) && [ -n "$KLOG" ]; then
    KERNEL_READ=1
  fi
  if [ "$KERNEL_READ" = 1 ]; then
    KERNEL=$(printf '%s\n' "$KLOG" | grep 'segfault' | grep -E 'php|apache2|httpd')
    if [ -n "$KERNEL" ]; then
      KCOUNT=$(printf '%s\n' "$KERNEL" | wc -l | tr -d ' ')
      echo "  ${KCOUNT} PHP/Apache segfault(s) in the kernel log"
      printf '%s\n' "$KERNEL" | tail -n 3 | safe | cut -c1-300 | sed 's/^/      /'
    fi
  elif [ "$IS_ROOT" = 1 ]; then
    echo "  Kernel log: not readable (inside a container the kernel log is usually not available)."
  else
    echo "  Kernel log: not readable (run as root)."
  fi
  CRASH_INCOMPLETE=$FILES_INCOMPLETE
  if [ "$KERNEL_READ" = 0 ]; then CRASH_INCOMPLETE=1; fi

  BIG=0
  SESS_INCOMPLETE=0
  for d in /var/lib/php/sessions /var/lib/php/session /var/lib/php5 /var/lib/php /tmp; do
    [ -d "$d" ] || continue
    if [ ! -r "$d" ] || [ ! -x "$d" ]; then
      echo "  $d: session directory not readable"
      SESS_INCOMPLETE=1
      continue
    fi
    n=$(find "$d" -maxdepth 1 -name 'sess_*' -size +1048576c 2>/dev/null | wc -l | tr -d ' ')
    if [ "$n" -gt 0 ]; then echo "  $d: ${n} session file(s) over 1 MB"; fi
    BIG=$((BIG + n))
  done

  OOM_OUT=$(count_or_unknown "$OOM_TOTAL" "$FILES_INCOMPLETE")
  CRASH_OUT=$(count_or_unknown "$((CRASH_TOTAL + KCOUNT))" "$CRASH_INCOMPLETE")
  BIG_OUT=$(count_or_unknown "$BIG" "$SESS_INCOMPLETE")
  echo "  Log files read: ${LOGS_READ}. Log files or directories that could not be read: ${LOGS_UNREAD}."
  echo "  Total: memory exhaustion errors ${OOM_OUT}, crashes ${CRASH_OUT}, large session files ${BIG_OUT}"
  case "$OOM_OUT $CRASH_OUT $BIG_OUT" in
    *unknown*) echo "  (unknown: a source for that count was not found or could not be read, so a 0 would not be reliable.)" ;;
  esac
  echo "  (These entries can also appear in normal operation. If they repeat right after unusual multipart requests, suspect an attack.)"
  add "log|oom|$OOM_OUT"
  add "log|crash|$CRASH_OUT"
  add "log|bigsession|$BIG_OUT"
fi

# ---------------------------------------------------------------- Recently changed PHP files (--webroot)
if [ -n "$WEBROOTS" ]; then
  section "PHP files changed in the last 3 days"
  RECENT=0
  WR_INCOMPLETE=0
  OLD_IFS=$IFS
  IFS=$NL
  set -f
  for dir in $WEBROOTS; do
    [ -n "$dir" ] || continue
    if [ ! -e "$dir" ]; then
      echo "  $dir: not found. Check the path."
      WR_INCOMPLETE=1
      continue
    elif [ ! -d "$dir" ]; then
      echo "  $dir: not a directory."
      WR_INCOMPLETE=1
      continue
    elif [ ! -r "$dir" ] || [ ! -x "$dir" ]; then
      echo "  $dir: not readable (run as root)."
      WR_INCOMPLETE=1
      continue
    fi
    # find -H follows the web root itself when it is a symbolic link (current -> releases/20261020).
    # Symbolic links to directories inside it (a shared uploads/) are scanned too, one level deep,
    # unless they point back into the web root or above it.
    top=$(cd "$dir" 2>/dev/null && pwd -P)
    prefix=${top%/}/
    roots=$dir
    seen=$NL$top$NL
    linked=0
    links=$(find -H "$dir" -type l 2>/dev/null)
    for l in $links; do
      [ -d "$l" ] || continue
      real=$(cd "$l" 2>/dev/null && pwd -P) || continue
      case "$real/" in "$prefix"*) continue ;; esac
      case "$prefix" in "${real%/}/"*) continue ;; esac
      case "$real" in /proc|/proc/*|/sys|/sys/*|/dev|/dev/*) continue ;; esac
      case "$seen" in *"$NL$real$NL"*) continue ;; esac
      seen=$seen$real$NL
      roots=$roots$NL$l
      linked=$((linked + 1))
    done
    files=""
    partial=0
    for r in $roots; do
      out=$(find -H "$r" -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' \) -mtime -3 2>/dev/null) || partial=1
      if [ -n "$out" ]; then files=$files$out$NL; fi
    done
    n=$(printf '%s' "$files" | grep -c .)
    note=""
    if [ "$linked" -gt 0 ]; then note=" (including ${linked} linked directory(ies) outside it)"; fi
    echo "  $dir: ${n} file(s)$note"
    printf '%s' "$files" | head -n 30 | safe | sed 's/^/      /'
    if [ "$partial" = 1 ]; then
      echo "      Some subdirectories could not be read, so files may be missing from this list (run as root)."
      WR_INCOMPLETE=1
    fi
    RECENT=$((RECENT + n))
  done
  set +f
  IFS=$OLD_IFS
  echo "  (Files changed by deployments are listed too. Check the contents of any file you do not recognise.)"
  add "webroot|recent_php|$(count_or_unknown "$RECENT" "$WR_INCOMPLETE")"
fi

# ---------------------------------------------------------------- Result block
echo
echo "Paste the block below into the check page. It holds OS release fields, package names and versions, process names, statuses and counts. No log lines and no file paths."
echo "-----BEGIN PHP2SHELL SERVERCHECK-----"
printf '%s' "$MACHINE" | sed '/^$/d' | safe
echo "-----END PHP2SHELL SERVERCHECK-----"
