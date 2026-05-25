#!/usr/bin/env bash

# Scans one or more IPs and ports for open HTTP services.
# Checks common agent metadata paths such as /agent.json and /.well-known/agent.json.
# Prints only relevant findings and supports quiet, balanced, and fast scan profiles.
#
# Options:
#   -t, --targets <list>      IP, comma-separated IPs, or last-octet range.
#                             Examples: 192.168.165.25
#                                       192.168.165.25,192.168.165.23
#                                       192.168.165.25-30
#
#   -p, --ports <list>        Port, comma-separated ports, range, or mixed list.
#                             Examples: 8000
#                                       8000,8001
#                                       8000-8010
#                                       8000,8001,8010-8020
#
#   --scheme <http|https|both>
#                             Scheme to test. Default: http
#
#   --profile <quiet|balanced|fast>
#                             Scan intensity. Default: balanced
#
#   --timeout <seconds>       Curl timeout. Overrides profile timeout.
#
#   -h, --help                Show help.

set -u

TARGET_SPEC="192.168.165.25"
PORT_SPEC="8000-8010"
SCHEME="http"
PROFILE="balanced"
TIMEOUT=""

PATHS=(
  "/.well-known/agent.json"
  "/agent.json"
  "/.well-known/ai-plugin.json"
)

show_help() {
    cat << EOF
Usage:
  $0 [options]

Description:
  Scans one or more IPs and ports, identifies open TCP ports with nmap,
  then checks common agent metadata paths over HTTP and/or HTTPS.

Options:
  -t, --targets <targets>
      Target IPs.

      Supported formats:
        Single IP:
          192.168.165.25

        Comma-separated IPs:
          192.168.165.25,192.168.165.23

        Last-octet range:
          192.168.165.25-30

      Note:
        Use full IPs when using commas.
        Correct: 192.168.165.25,192.168.165.23
        Avoid:   192.168.165.25,23

  -p, --ports <ports>
      Ports to scan.

      Supported formats:
        Single port:
          8000

        Comma-separated ports:
          8000,8001

        Port range:
          8000-8010

        Mixed:
          8000,8001,8010-8020

  --scheme <http|https|both>
      Scheme to test.
      Default: http

  --profile <quiet|balanced|fast>
      Scan intensity.

      quiet:
        Lower nmap timing and longer curl timeout.
        Better for sensitive or high-alert environments.

      balanced:
        Good default for internal assessments.

      fast:
        Faster scan, more aggressive timing.
        Better when speed matters and alerting/noise is acceptable.

      Default: balanced

  --timeout <seconds>
      Curl timeout in seconds.
      Overrides the timeout selected by the profile.

  -h, --help
      Show this help message.

Examples:
  $0 -t 192.168.165.25 -p 8000-8010

  $0 -t 192.168.165.25,192.168.165.23 -p 8000,8001

  $0 -t 192.168.165.25-30 -p 8000-8010 --profile quiet

  $0 -t 192.168.165.25-30 -p 8000,8001,8010-8020 --scheme both --profile fast
EOF
}

die() {
    echo "[!] $*" >&2
    exit 1
}

validate_ip() {
    local ip="$1"

    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1

    local IFS='.'
    local -a octets
    read -r -a octets <<< "$ip"

    for octet in "${octets[@]}"; do
        (( octet >= 0 && octet <= 255 )) || return 1
    done

    return 0
}

validate_port() {
    local port="$1"

    [[ "$port" =~ ^[0-9]+$ ]] || return 1
    (( port >= 1 && port <= 65535 )) || return 1

    return 0
}

expand_targets() {
    local spec="$1"
    local item

    IFS=',' read -ra items <<< "$spec"

    for item in "${items[@]}"; do
        item="$(echo "$item" | xargs)"

        [[ -z "$item" ]] && continue

        if [[ "$item" =~ ^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)([0-9]{1,3})-([0-9]{1,3})$ ]]; then
            local prefix="${BASH_REMATCH[1]}"
            local start="${BASH_REMATCH[2]}"
            local end="${BASH_REMATCH[3]}"

            (( start <= end )) || die "Invalid IP range: $item"

            for ((i=start; i<=end; i++)); do
                local ip="${prefix}${i}"
                validate_ip "$ip" || die "Invalid generated IP: $ip"
                echo "$ip"
            done

        elif validate_ip "$item"; then
            echo "$item"

        else
            die "Invalid target format: $item"
        fi
    done
}

expand_ports() {
    local spec="$1"
    local item

    IFS=',' read -ra items <<< "$spec"

    for item in "${items[@]}"; do
        item="$(echo "$item" | xargs)"

        [[ -z "$item" ]] && continue

        if [[ "$item" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            local start="${BASH_REMATCH[1]}"
            local end="${BASH_REMATCH[2]}"

            validate_port "$start" || die "Invalid start port: $start"
            validate_port "$end" || die "Invalid end port: $end"
            (( start <= end )) || die "Invalid port range: $item"

            for ((p=start; p<=end; p++)); do
                echo "$p"
            done

        elif validate_port "$item"; then
            echo "$item"

        else
            die "Invalid port format: $item"
        fi
    done
}

apply_profile() {
    case "$PROFILE" in
        quiet)
            NMAP_TIMING="-T2"
            CURL_SLEEP="0.40"
            [[ -z "$TIMEOUT" ]] && TIMEOUT="6"
            ;;
        balanced)
            NMAP_TIMING="-T3"
            CURL_SLEEP="0.10"
            [[ -z "$TIMEOUT" ]] && TIMEOUT="4"
            ;;
        fast)
            NMAP_TIMING="-T4"
            CURL_SLEEP="0"
            [[ -z "$TIMEOUT" ]] && TIMEOUT="2"
            ;;
        *)
            die "Invalid profile: $PROFILE. Use quiet, balanced, or fast."
            ;;
    esac
}

validate_options() {
    case "$SCHEME" in
        http|https|both)
            ;;
        *)
            die "Invalid scheme: $SCHEME. Use http, https, or both."
            ;;
    esac

    if [[ -n "$TIMEOUT" ]]; then
        [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || die "Timeout must be a number."
        (( TIMEOUT >= 1 )) || die "Timeout must be greater than 0."
    fi

    command -v nmap >/dev/null 2>&1 || die "nmap is not installed or not in PATH."
    command -v curl >/dev/null 2>&1 || die "curl is not installed or not in PATH."
}

build_urls() {
    local target="$1"
    local port="$2"
    local path="$3"

    case "$SCHEME" in
        http)
            echo "http://${target}:${port}${path}"
            ;;
        https)
            echo "https://${target}:${port}${path}"
            ;;
        both)
            echo "http://${target}:${port}${path}"
            echo "https://${target}:${port}${path}"
            ;;
    esac
}

scan_open_ports() {
    local target="$1"
    local ports_csv="$2"

    nmap -sT -p"$ports_csv" "$NMAP_TIMING" "$target" 2>/dev/null |
        awk '/^[0-9]+\/tcp[[:space:]]+open/ {split($1,a,"/"); print a[1]}'
}

check_metadata_url() {
    local url="$1"
    local response
    local curl_exit

    response="$(curl -k -s --max-time "$TIMEOUT" "$url")"
    curl_exit=$?

    if [[ $curl_exit -ne 0 || -z "$response" ]]; then
        return 1
    fi

    if command -v jq >/dev/null 2>&1; then
        if echo "$response" | jq . >/dev/null 2>&1; then
            echo "$response" | jq .
            return 0
        fi
    else
        echo "$response"
        return 0
    fi

    return 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--targets)
            TARGET_SPEC="${2:-}"
            shift 2
            ;;

        --targets=*)
            TARGET_SPEC="${1#*=}"
            shift
            ;;

        -p|--ports)
            PORT_SPEC="${2:-}"
            shift 2
            ;;

        --ports=*)
            PORT_SPEC="${1#*=}"
            shift
            ;;

        --scheme)
            SCHEME="${2:-}"
            shift 2
            ;;

        --scheme=*)
            SCHEME="${1#*=}"
            shift
            ;;

        --profile)
            PROFILE="${2:-}"
            shift 2
            ;;

        --profile=*)
            PROFILE="${1#*=}"
            shift
            ;;

        --timeout)
            TIMEOUT="${2:-}"
            shift 2
            ;;

        --timeout=*)
            TIMEOUT="${1#*=}"
            shift
            ;;

        -h|--help)
            show_help
            exit 0
            ;;

        *)
            die "Unknown option: $1. Use -h for help."
            ;;
    esac
done

validate_options
apply_profile

mapfile -t TARGETS < <(expand_targets "$TARGET_SPEC" | sort -u)
mapfile -t PORTS < <(expand_ports "$PORT_SPEC" | sort -n -u)

if [[ "${#TARGETS[@]}" -eq 0 ]]; then
    die "No valid targets generated."
fi

if [[ "${#PORTS[@]}" -eq 0 ]]; then
    die "No valid ports generated."
fi

PORTS_CSV="$(IFS=','; echo "${PORTS[*]}")"

echo "[*] Targets: ${TARGETS[*]}"
echo "[*] Ports: $PORTS_CSV"
echo "[*] Scheme: $SCHEME"
echo "[*] Profile: $PROFILE"
echo "[*] Timeout: ${TIMEOUT}s"
echo

TOTAL_FOUND=0

for target in "${TARGETS[@]}"; do
    echo "=================================================="
    echo "[*] Scanning target: $target"

    OPEN_PORTS="$(scan_open_ports "$target" "$PORTS_CSV")"

    if [[ -z "$OPEN_PORTS" ]]; then
        echo "[!] No open ports found on $target"
        echo
        continue
    fi

    echo "[+] Open ports on $target:"
    echo "$OPEN_PORTS" | sed 's/^/    - /'
    echo

    while read -r port; do
        [[ -z "$port" ]] && continue

        echo "--------------------------------------------------"
        echo "[*] Checking $target:$port"

        FOUND=0

        for path in "${PATHS[@]}"; do
            while read -r url; do
                [[ -z "$url" ]] && continue

                echo "[*] Trying $url"

                RESPONSE="$(check_metadata_url "$url")"
                RESULT=$?

                if [[ $RESULT -eq 0 ]]; then
                    echo "[+] Agent metadata found:"
                    echo "[+] URL: $url"
                    echo "$RESPONSE"
                    FOUND=1
                    TOTAL_FOUND=$((TOTAL_FOUND + 1))
                    break 2
                fi

                if [[ "$CURL_SLEEP" != "0" ]]; then
                    sleep "$CURL_SLEEP"
                fi

            done < <(build_urls "$target" "$port" "$path")
        done

        if [[ $FOUND -eq 0 ]]; then
            echo "[!] No agent metadata found on $target:$port"
        fi

        echo
    done <<< "$OPEN_PORTS"
done

echo "=================================================="
echo "[*] Scan completed."
echo "[*] Metadata findings: $TOTAL_FOUND"
