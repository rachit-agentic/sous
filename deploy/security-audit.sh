#!/usr/bin/env bash
# Read-only host audit for a Sous installation provisioned by setup-server.sh.
set -u
set -o pipefail
export LC_ALL=C

usage() {
  cat <<'HELP'
Usage: sudo bash deploy/security-audit.sh DOMAIN [DEPLOY_USER]
Example: sudo bash deploy/security-audit.sh sous.rachitjaiswal.com sous-deploy

Checks the Ubuntu/Debian host, using only local files and loopback connections.
No credentials are printed. AWS security groups and IAM, public reachability,
installed package vulnerabilities, and application authorization are out of scope.
Exit codes: 0 no failures (review warnings), 1 findings, 2 bad arguments or no root.
HELP
}

if [[ ${1:-} == --help || ${1:-} == -h ]]; then usage; exit 0; fi
domain=${1:-}
deploy_user=${2:-sous-deploy}
if (( $# < 1 || $# > 2 )) ||
  ! [[ $domain =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,63}$ &&
       $deploy_user =~ ^[a-z_][a-z0-9_-]*$ && $deploy_user != root ]]; then
  usage >&2
  exit 2
fi
if (( EUID != 0 )); then printf 'Run this audit with sudo.\n' >&2; exit 2; fi

failures=0
warnings=0
pass() { printf 'PASS  %s\n' "$1"; }
warn() { printf 'WARN  %s\n' "$1"; warnings=$((warnings + 1)); }
fail() { printf 'FAIL  %s\n' "$1"; failures=$((failures + 1)); }

printf 'Sous host audit: %s (deploy user: %s)\n\n' "$domain" "$deploy_user"

if ssh_config=$(sshd -T 2>/dev/null); then
  # sshd -T without a connection spec reports the global/default policy.
  if grep -qx 'permitrootlogin no' <<< "$ssh_config"; then
    pass 'SSH disables direct root login in its default policy.'
  else
    warn 'SSH default policy permits some form of direct root login. Review PermitRootLogin.'
  fi
  if grep -qx 'passwordauthentication no' <<< "$ssh_config" &&
    grep -qx 'kbdinteractiveauthentication no' <<< "$ssh_config"; then
    pass 'SSH disables password and keyboard-interactive authentication by default.'
  else
    warn 'SSH default policy allows password or keyboard-interactive authentication.'
  fi
else
  warn 'Could not read the effective SSH defaults with sshd -T.'
fi

if deploy_home=$(getent passwd "$deploy_user" | cut -d: -f6) && [[ -n $deploy_home ]]; then
  if [[ ! -L $deploy_home/.ssh && -f $deploy_home/.ssh/authorized_keys && ! -L $deploy_home/.ssh/authorized_keys ]] &&
    [[ $(stat -c '%U %a' -- "$deploy_home/.ssh") == "$deploy_user 700" ]] &&
    [[ $(stat -c '%U %a' -- "$deploy_home/.ssh/authorized_keys") == "$deploy_user 600" ]]; then
    pass 'The deploy account owns its SSH directory and authorized_keys with private modes.'
  else
    fail 'Check the deploy account’s .ssh and authorized_keys ownership and modes (700/600).'
  fi
  if id -nG "$deploy_user" | tr ' ' '\n' | grep -qx docker; then
    warn 'The deploy account has Docker group access, which is equivalent to root access. Review its authorized keys.'
  fi
else
  fail 'The specified deploy account does not exist.'
fi

if [[ -f /opt/sous/.env && ! -L /opt/sous/.env ]] &&
  [[ $(stat -c '%U %a' -- /opt/sous/.env) == "$deploy_user 600" ]]; then
  pass 'The deploy account owns /opt/sous/.env with mode 600.'
else
  fail 'Check /opt/sous/.env ownership and mode 600.'
fi

if listeners=$(ss -H -ltn 'sport = :5050' 2>/dev/null); then
  if [[ -z $listeners ]]; then
    warn 'Nothing is listening on port 5050. Sous may not be deployed yet.'
  elif awk '$4 !~ /^(127\.[0-9]+\.[0-9]+\.[0-9]+|\[::1\]):5050$/ {bad=1} END {exit bad}' <<< "$listeners"; then
    pass 'Port 5050 listens only on loopback.'
  else
    fail 'Port 5050 listens on a non-loopback address. Review Docker port publishing.'
  fi
else
  warn 'Could not inspect port 5050 with ss.'
fi

if published_ports=$(timeout 5 docker --host unix:///var/run/docker.sock ps --format '{{.Ports}}' 2>/dev/null); then
  # Docker can forward ports through firewall rules without a listening process in ss.
  if awk -F ',' '{for (i=1; i<=NF; i++) if ($i ~ /:5050->/ &&
    $i !~ /^ *(127\.[0-9]+\.[0-9]+\.[0-9]+|\[::1\]):5050->/) bad=1} END {exit bad}' <<< "$published_ports"; then
    pass 'Docker reports no non-loopback mappings for host port 5050.'
  else
    fail 'Docker publishes host port 5050 on a non-loopback address.'
  fi
else
  warn 'Could not inspect Docker port mappings on the local daemon.'
fi

if curl -q --noproxy '*' --silent --fail --max-time 5 --output /dev/null \
  http://127.0.0.1:5050/healthz; then
  pass 'Sous responds to the loopback health check.'
else
  warn 'Sous did not pass the loopback health check.'
fi

if status=$(curl -q --noproxy '*' --silent --max-time 5 --output /dev/null \
  --write-out '%{http_code}' --resolve "$domain:443:127.0.0.1" "https://$domain/"); then
  if [[ $status == 401 ]]; then
    pass 'Local HTTPS has a trusted certificate and denies a request without credentials.'
  else
    fail "Expected HTTP 401 from local HTTPS without credentials, got $status. Check Nginx authentication."
  fi
else
  fail 'Could not validate local HTTPS. Check Nginx, certificate trust, and the requested hostname.'
fi

cert="/etc/letsencrypt/live/$domain/fullchain.pem"
if [[ ! -r $cert ]]; then
  warn 'Could not locate the expected Certbot certificate to check renewal.'
elif openssl x509 -checkend 2592000 -noout -in "$cert" >/dev/null 2>&1; then
  pass 'The Certbot certificate expires in more than 30 days.'
else
  warn 'The Certbot certificate could not be read by OpenSSL or expires within 30 days.'
fi

if systemctl is-active --quiet apt-daily-upgrade.timer; then
  pass 'The APT upgrade timer is active. Verify that security updates are applied.'
else
  warn 'The APT upgrade timer is inactive or unavailable. Verify how security updates are applied.'
fi

printf '\n%d failure(s), %d warning(s). AWS-side controls and package CVEs were not checked.\n' "$failures" "$warnings"
if (( failures > 0 )); then exit 1; fi
exit 0
