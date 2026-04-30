#!/usr/bin/env bash
# test-tls-profile.sh — manual helper for testing the APIServer TLS profile
# path through the observability-operator to the monitoring-console-plugin deployment.
#
# Usage:
#   ./hack/test-tls-profile.sh set <profile>   # patch APIServer and wait for operator restart
#   ./hack/test-tls-profile.sh check            # show current TLS args on the plugin deployment
#   ./hack/test-tls-profile.sh probe            # port-forward to health-analyzer and run openssl handshake
#   ./hack/test-tls-profile.sh restore          # put back the original profile
#
# Profiles accepted by 'set': modern | intermediate | old | custom
# For 'custom', set CUSTOM_CIPHERS and CUSTOM_MIN_VERSION env vars before calling.
#
# Environment variables (all optional):
#   OPERATOR_NS          namespace the operator runs in (default: openshift-cluster-observability-operator)
#   PLUGIN_NS            namespace the plugin deployment lives in (default: same as OPERATOR_NS)
#   PLUGIN_DEPLOY        name of the monitoring plugin deployment (default: monitoring)
#   CUSTOM_CIPHERS       comma-separated OpenSSL cipher list for the 'custom' profile
#   CUSTOM_MIN_VERSION   VersionTLS12 or VersionTLS13 for the 'custom' profile
#   RESTART_TIMEOUT      seconds to wait for operator pod restart (default: 120)
#   PROBE_LOCAL_PORT     local port used for the port-forward during 'probe' (default: 18443)
#   PROBE_TIMEOUT        seconds to wait for port-forward readiness (default: 15)

set -euo pipefail

# ── defaults ──────────────────────────────────────────────────────────────────
OPERATOR_NS="${OPERATOR_NS:-openshift-cluster-observability-operator}"
PLUGIN_NS="${PLUGIN_NS:-${OPERATOR_NS}}"
PLUGIN_DEPLOY="${PLUGIN_DEPLOY:-monitoring}"
RESTART_TIMEOUT="${RESTART_TIMEOUT:-120}"
PROBE_LOCAL_PORT="${PROBE_LOCAL_PORT:-18443}"
PROBE_TIMEOUT="${PROBE_TIMEOUT:-15}"

SNAPSHOT_FILE="/tmp/apiserver-tls-snapshot.json"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── helpers ───────────────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}[info]${NC}  $*"; }
ok()      { echo -e "${GREEN}[ok]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[warn]${NC}  $*"; }
die()     { echo -e "${RED}[error]${NC} $*" >&2; exit 1; }

require() {
    for cmd in "$@"; do
        command -v "$cmd" &>/dev/null || die "'$cmd' not found on PATH"
    done
}

# ── sub-commands ──────────────────────────────────────────────────────────────

cmd_check() {
    info "Current TLS profile on APIServer cluster:"
    oc get apiserver cluster \
        -o jsonpath='{.spec.tlsSecurityProfile}' 2>/dev/null \
        | python3 -m json.tool 2>/dev/null || echo "(none — cluster default)"
    echo

    _check_deployment "${PLUGIN_DEPLOY}" "${PLUGIN_NS}"
    _check_deployment "health-analyzer" "${PLUGIN_NS}"
}

_check_deployment() {
    local deploy_name="$1"
    local ns="$2"

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    info "Deployment: ${deploy_name} (namespace: ${ns})"
    echo

    if ! oc -n "${ns}" get deployment "${deploy_name}" &>/dev/null; then
        warn "  Deployment '${deploy_name}' not found in '${ns}'."
        if [[ "${deploy_name}" == "${PLUGIN_DEPLOY}" ]]; then
            warn "  Create a Monitoring UIPlugin first:"
            warn "    oc apply -f - <<EOF"
            warn "    apiVersion: observability.openshift.io/v1alpha1"
            warn "    kind: UIPlugin"
            warn "    metadata:"
            warn "      name: monitoring"
            warn "    spec:"
            warn "      type: Monitoring"
            warn "    EOF"
        fi
        echo
        return
    fi

    info "  All container args:"
    oc -n "${ns}" get deployment "${deploy_name}" \
        -o jsonpath='{.spec.template.spec.containers[0].args}' \
        | tr ',' '\n' | tr -d '[]"' \
        | while IFS= read -r arg; do echo "    ${arg}"; done
    echo

    info "  TLS-specific args:"
    local tls_args
    tls_args=$(oc -n "${ns}" get deployment "${deploy_name}" \
        -o jsonpath='{.spec.template.spec.containers[0].args}' \
        | tr ',' '\n' | tr -d '[]"' \
        | grep -E 'tls-min-version|tls-cipher-suites' || true)

    if [[ -n "${tls_args}" ]]; then
        echo "${tls_args}" | while IFS= read -r arg; do ok "    ${arg}"; done
    else
        warn "    No -tls-min-version / -tls-cipher-suites / --tls-min-version / --tls-cipher-suites args found."
    fi
    echo
}

cmd_set() {
    local profile="${1:-}"
    [[ -z "${profile}" ]] && die "Usage: $0 set <modern|intermediate|old|custom>"

    # Snapshot current state before touching anything
    if [[ ! -f "${SNAPSHOT_FILE}" ]]; then
        info "Saving current APIServer TLS profile to ${SNAPSHOT_FILE}..."
        oc get apiserver cluster -o json \
            | python3 -c "
import sys, json
obj = json.load(sys.stdin)
snapshot = {'tlsSecurityProfile': obj.get('spec', {}).get('tlsSecurityProfile')}
print(json.dumps(snapshot, indent=2))
" > "${SNAPSHOT_FILE}"
        ok "Snapshot saved. Run '$0 restore' when done to put it back."
    else
        warn "Snapshot already exists at ${SNAPSHOT_FILE}. Skipping re-snapshot."
        warn "If you want a fresh snapshot, delete the file first."
    fi

    local patch
    case "${profile}" in
        modern)
            patch='{"spec":{"tlsSecurityProfile":{"type":"Modern","modern":{}}}}'
            ;;
        intermediate)
            patch='{"spec":{"tlsSecurityProfile":{"type":"Intermediate","intermediate":{}}}}'
            ;;
        old)
            patch='{"spec":{"tlsSecurityProfile":{"type":"Old","old":{}}}}'
            ;;
        custom)
            local ciphers="${CUSTOM_CIPHERS:-ECDHE-ECDSA-AES128-GCM-SHA256,ECDHE-RSA-AES256-GCM-SHA384}"
            local min_ver="${CUSTOM_MIN_VERSION:-VersionTLS12}"
            # Build the JSON cipher array from the comma-separated list
            local cipher_json
            cipher_json=$(python3 -c "
import sys, json
print(json.dumps([c.strip() for c in '${ciphers}'.split(',')]))
")
            patch=$(python3 -c "
import json
print(json.dumps({
  'spec': {
    'tlsSecurityProfile': {
      'type': 'Custom',
      'custom': {
        'ciphers': ${cipher_json},
        'minTLSVersion': '${min_ver}'
      }
    }
  }
}))
")
            ;;
        *)
            die "Unknown profile '${profile}'. Choose: modern | intermediate | old | custom"
            ;;
    esac

    info "Patching APIServer cluster with '${profile}' TLS profile..."
    oc patch apiserver cluster --type=merge -p "${patch}"
    ok "APIServer patched."

    _wait_for_operator_restart
    _wait_for_deployment_update
    echo
    ok "Done. Run '$0 check' to inspect the resulting TLS args."
}

cmd_restore() {
    if [[ ! -f "${SNAPSHOT_FILE}" ]]; then
        die "No snapshot found at ${SNAPSHOT_FILE}. Nothing to restore."
    fi

    local original_profile
    original_profile=$(python3 -c "
import sys, json
snap = json.load(open('${SNAPSHOT_FILE}'))
print(json.dumps(snap.get('tlsSecurityProfile')))
")

    if [[ "${original_profile}" == "null" ]]; then
        info "Original profile was unset — removing tlsSecurityProfile from APIServer..."
        oc patch apiserver cluster --type=json \
            -p '[{"op":"remove","path":"/spec/tlsSecurityProfile"}]' 2>/dev/null \
            || warn "Nothing to remove (already unset)."
    else
        info "Restoring original TLS profile: ${original_profile}"
        local patch
        patch=$(python3 -c "
import json
profile = ${original_profile}
print(json.dumps({'spec': {'tlsSecurityProfile': profile}}))
")
        oc patch apiserver cluster --type=merge -p "${patch}"
    fi

    rm -f "${SNAPSHOT_FILE}"
    ok "Restored. Snapshot deleted."

    _wait_for_operator_restart
    _wait_for_deployment_update
}

# Module-level state for probe cleanup (accessible by the trap handler).
_PROBE_PF_PID=""
_PROBE_CA_FILE=""

_probe_cleanup() {
    if [[ -n "${_PROBE_PF_PID}" ]] && kill -0 "${_PROBE_PF_PID}" 2>/dev/null; then
        kill "${_PROBE_PF_PID}" 2>/dev/null || true
        wait "${_PROBE_PF_PID}" 2>/dev/null || true
    fi
    _PROBE_PF_PID=""
    [[ -n "${_PROBE_CA_FILE}" && -f "${_PROBE_CA_FILE}" ]] && rm -f "${_PROBE_CA_FILE}"
    _PROBE_CA_FILE=""
}

cmd_probe() {
    local ha_ns="${PLUGIN_NS}"
    local ha_svc="health-analyzer"
    local ha_port=8443
    local local_port="${PROBE_LOCAL_PORT}"
    local sni="${ha_svc}.${ha_ns}.svc"
    _PROBE_CA_FILE="/tmp/ocp-service-ca.crt"

    # ── preflight ──────────────────────────────────────────────────────────────
    require openssl

    info "Checking for health-analyzer service in '${ha_ns}'..."
    if ! oc -n "${ha_ns}" get service "${ha_svc}" &>/dev/null; then
        die "Service '${ha_svc}' not found in namespace '${ha_ns}'.\n" \
            "       Make sure a Monitoring UIPlugin with ClusterHealthAnalyzer enabled exists."
    fi

    # ── find a ready pod ───────────────────────────────────────────────────────
    info "Looking for a Ready health-analyzer pod..."
    local pod
    pod=$(oc -n "${ha_ns}" get pods \
        -l "app.kubernetes.io/instance=${ha_svc}" \
        --field-selector=status.phase=Running \
        --no-headers \
        -o custom-columns=NAME:.metadata.name 2>/dev/null | head -1)

    if [[ -z "${pod}" ]]; then
        die "No Running health-analyzer pod found in '${ha_ns}'."
    fi
    ok "Using pod: ${pod}"

    # ── fetch OpenShift service CA ─────────────────────────────────────────────
    info "Fetching OpenShift service CA certificate..."
    oc -n openshift-config get configmap openshift-service-ca.crt \
        -o jsonpath='{.data.service-ca\.crt}' > "${_PROBE_CA_FILE}" 2>/dev/null \
        || die "Could not retrieve openshift-service-ca.crt ConfigMap from openshift-config."
    ok "Service CA saved to ${_PROBE_CA_FILE}"

    # ── start port-forward ─────────────────────────────────────────────────────
    # Kill any stale port-forward left from a previous run on the same port.
    fuser -k "${local_port}/tcp" &>/dev/null || true

    info "Starting port-forward: localhost:${local_port} → ${pod}:${ha_port}..."
    oc -n "${ha_ns}" port-forward "pod/${pod}" "${local_port}:${ha_port}" \
        >/tmp/pf-health-analyzer.log 2>&1 &
    _PROBE_PF_PID=$!

    trap '_probe_cleanup' EXIT INT TERM

    # Wait until the port-forward is accepting connections.
    local deadline=$(( $(date +%s) + PROBE_TIMEOUT ))
    while ! (echo > /dev/tcp/127.0.0.1/${local_port}) 2>/dev/null; do
        if (( $(date +%s) > deadline )); then
            die "Port-forward did not become ready within ${PROBE_TIMEOUT}s.\n" \
                "       Check: cat /tmp/pf-health-analyzer.log"
        fi
        sleep 1
    done
    ok "Port-forward is ready on localhost:${local_port}"

    # ── openssl handshake ──────────────────────────────────────────────────────
    echo
    info "Running TLS handshake against localhost:${local_port} (SNI: ${sni})..."
    echo "─────────────────────────────────────────────────────────────────────"

    local openssl_out
    openssl_out=$(printf 'GET /metrics HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "${sni}" \
        | openssl s_client \
            -connect "127.0.0.1:${local_port}" \
            -servername "${sni}" \
            -CAfile "${_PROBE_CA_FILE}" \
            -showcerts \
            2>&1) || true

    echo "${openssl_out}"
    echo "─────────────────────────────────────────────────────────────────────"

    # ── parsed summary ─────────────────────────────────────────────────────────
    echo
    info "Handshake summary:"

    local protocol cipher verify
    protocol=$(echo "${openssl_out}" | grep -E "^\s+Protocol\s*:" | awk -F: '{print $2}' | xargs)
    cipher=$(echo "${openssl_out}"   | grep -E "^\s+Cipher\s*:"   | awk -F: '{print $2}' | xargs)
    verify=$(echo "${openssl_out}"   | grep "Verify return code"   | awk -F: '{print $2}' | xargs)

    if [[ -n "${protocol}" ]]; then
        ok "  Protocol : ${protocol}"
    else
        warn "  Protocol : (not found in output)"
    fi

    if [[ -n "${cipher}" ]]; then
        ok "  Cipher   : ${cipher}"
    else
        warn "  Cipher   : (not found in output)"
    fi

    if [[ "${verify}" == *"ok"* ]] || [[ "${verify}" == *"0 (ok)"* ]]; then
        ok "  Cert verify: ${verify}"
    else
        warn "  Cert verify: ${verify:-unknown}"
    fi

    # Cross-check against what the deployment is configured with.
    echo
    info "Configured TLS args on the health-analyzer deployment:"
    oc -n "${ha_ns}" get deployment "${ha_svc}" \
        -o jsonpath='{.spec.template.spec.containers[0].args}' 2>/dev/null \
        | tr ',' '\n' | tr -d '[]"' \
        | grep -E 'tls-min-version|tls-cipher-suites' \
        || warn "  No --tls-min-version / --tls-cipher-suites args found on deployment."
    echo

    _probe_cleanup
    trap - EXIT INT TERM
}

# ── internal waits ────────────────────────────────────────────────────────────

_wait_for_operator_restart() {
    info "Waiting for operator pod to cycle in '${OPERATOR_NS}' (timeout: ${RESTART_TIMEOUT}s)..."

    # Capture the current operator pod name(s) before the restart
    local old_pods
    old_pods=$(oc -n "${OPERATOR_NS}" get pods -l app.kubernetes.io/name=observability-operator \
        --no-headers -o custom-columns=NAME:.metadata.name 2>/dev/null || true)

    if [[ -z "${old_pods}" ]]; then
        warn "Could not find operator pods with label app.kubernetes.io/name=observability-operator."
        warn "Skipping restart wait — check operator logs manually."
        return
    fi

    info "Current operator pod(s): ${old_pods}"
    info "Waiting for new pod to appear..."

    local deadline=$(( $(date +%s) + RESTART_TIMEOUT ))
    while true; do
        local new_pods
        new_pods=$(oc -n "${OPERATOR_NS}" get pods -l app.kubernetes.io/name=observability-operator \
            --no-headers -o custom-columns=NAME:.metadata.name 2>/dev/null || true)

        # Check if the set of pods has changed (restart produces a new pod name)
        if [[ "${new_pods}" != "${old_pods}" ]] && [[ -n "${new_pods}" ]]; then
            ok "New operator pod detected: ${new_pods}"
            break
        fi

        if (( $(date +%s) > deadline )); then
            warn "Timed out waiting for operator pod restart."
            warn "The SecurityProfileWatcher triggers a graceful restart only when the profile"
            warn "actually differs from the initial value fetched at startup."
            break
        fi
        sleep 5
    done

    # Wait for the new pod to become Ready
    info "Waiting for operator pod to become Ready..."
    oc -n "${OPERATOR_NS}" wait pods \
        -l app.kubernetes.io/name=observability-operator \
        --for=condition=Ready \
        --timeout="${RESTART_TIMEOUT}s" 2>/dev/null \
        && ok "Operator pod is Ready." \
        || warn "Timed out waiting for Ready — check 'oc -n ${OPERATOR_NS} get pods'"
}

_wait_for_deployment_update() {
    if ! oc -n "${PLUGIN_NS}" get deployment "${PLUGIN_DEPLOY}" &>/dev/null; then
        warn "Plugin deployment '${PLUGIN_DEPLOY}' not found — skipping deployment rollout wait."
        return
    fi

    info "Waiting for plugin deployment '${PLUGIN_DEPLOY}' rollout..."
    oc -n "${PLUGIN_NS}" rollout status deployment/"${PLUGIN_DEPLOY}" \
        --timeout="${RESTART_TIMEOUT}s" \
        && ok "Plugin deployment is up to date." \
        || warn "Rollout did not finish in time — check 'oc -n ${PLUGIN_NS} rollout status deployment/${PLUGIN_DEPLOY}'"
}

# ── main ──────────────────────────────────────────────────────────────────────

require oc python3

subcommand="${1:-}"
shift || true

case "${subcommand}" in
    check)   cmd_check ;;
    set)     cmd_set "$@" ;;
    probe)   cmd_probe ;;
    restore) cmd_restore ;;
    *)
        echo "Usage: $0 <check|set|probe|restore>"
        echo
        echo "  check              Show the current APIServer TLS profile and plugin deployment TLS args"
        echo "  set <profile>      Patch the APIServer and wait for the operator + plugin to converge"
        echo "                     Profiles: modern | intermediate | old | custom"
        echo "  probe              Port-forward to health-analyzer:8443 and run an openssl handshake"
        echo "                     to verify the negotiated TLS version and cipher suite"
        echo "  restore            Revert the APIServer to the state before 'set' was called"
        echo
        echo "Environment variables:"
        echo "  OPERATOR_NS        Operator namespace (default: openshift-cluster-observability-operator)"
        echo "  PLUGIN_NS          Plugin deployment namespace (default: OPERATOR_NS)"
        echo "  PLUGIN_DEPLOY      Plugin deployment name (default: monitoring)"
        echo "  CUSTOM_CIPHERS     Comma-separated OpenSSL ciphers for 'custom' profile"
        echo "  CUSTOM_MIN_VERSION VersionTLS12 or VersionTLS13 for 'custom' profile"
        echo "  RESTART_TIMEOUT    Seconds to wait for restarts (default: 120)"
        echo "  PROBE_LOCAL_PORT   Local port for port-forward during 'probe' (default: 18443)"
        echo "  PROBE_TIMEOUT      Seconds to wait for port-forward readiness (default: 15)"
        echo
        echo "Examples:"
        echo "  $0 check"
        echo "  $0 set modern"
        echo "  $0 set intermediate"
        echo "  CUSTOM_CIPHERS=ECDHE-RSA-AES128-GCM-SHA256 CUSTOM_MIN_VERSION=VersionTLS13 $0 set custom"
        echo "  $0 probe"
        echo "  $0 restore"
        exit 1
        ;;
esac
