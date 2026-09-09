#!/bin/sh
set -eu

mode=${1:-fullnode}
case "$mode" in
  fullnode) binary=tron-fullnode; deployment=fullnode.deployment.json ;;
  solidity) binary=tron-solidity; deployment=solidity.deployment.json ;;
  *) echo "mode must be fullnode or solidity" >&2; exit 64 ;;
esac
shift || :
compose_profiles=${TRON_COMPOSE_PROFILES:-}
case "$compose_profiles" in
  ""|full|solidity) ;;
  *) echo "multiple or unknown Compose profiles are forbidden" >&2; exit 64 ;;
esac
case "$mode:$compose_profiles" in
  fullnode:""|solidity:""|fullnode:full|solidity:solidity) ;;
  *) echo "Compose profile does not match the selected node mode" >&2; exit 64 ;;
esac


candidate=${TRON_RELEASE_CANDIDATE:-/run/tron/candidate}
trust_store=${TRON_RELEASE_TRUST_STORE:-/run/tron/release-trust-store.json}
prefix=${TRON_INSTALL_PREFIX:-/opt/tron}
receipt=${TRON_INSTALL_RECEIPT:-/var/lib/tron/install-receipt.json}
manifest=${TRON_RELEASE_MANIFEST:-$candidate/release-manifest.dsse.json}
bundle=${TRON_RELEASE_BUNDLE:-$candidate/bundle}
verification_time=${TRON_VERIFICATION_TIME:-}
channel=${TRON_RELEASE_CHANNEL:-stable}
minimum_sequence=${TRON_MINIMUM_RELEASE_SEQUENCE:-1}

test -n "$verification_time" || { echo "TRON_VERIFICATION_TIME must be an explicit trusted RFC3339 UTC time" >&2; exit 64; }

case "$verification_time" in
  [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z) ;;
  *) echo "TRON_VERIFICATION_TIME must be RFC3339 UTC (YYYY-MM-DDTHH:MM:SSZ)" >&2; exit 64 ;;
esac
date_part=${verification_time%%T*}
time_part=${verification_time#*T}
time_part=${time_part%Z}
if test -x /bin/busybox; then
  normalized_time=$(/bin/busybox date -u -d "$date_part $time_part" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null) || normalized_time=
else
  normalized_time=$(date -u -d "$date_part $time_part" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null) || normalized_time=
fi
test "$normalized_time" = "$verification_time" || { echo "TRON_VERIFICATION_TIME is not a valid RFC3339 UTC instant" >&2; exit 64; }


for path in "$manifest" "$trust_store" "$bundle" "/etc/tron/snapshot-trust-store.json" "/etc/tron/backup-keyring.txt" "/var/lib/tron/parameters/sapling-spend.params" "/var/lib/tron/parameters/sapling-output.params"; do
  test -r "$path" || { echo "mandatory deployment material is not readable: $path" >&2; exit 66; }
done

if test -e "$receipt"; then
  /usr/local/bin/tron-release-verify verify-install \
    --trust-store "$trust_store" \
    --manifest "$manifest" \
    --bundle "$bundle" \
    --platform P-LINUX-X64 \
    --channel "$channel" \
    --minimum-sequence "$minimum_sequence" \
    --receipt "$receipt" \
    --prefix "$prefix/current" \
    --verification-time "$verification_time"
else
  # The candidate is a read-only bind mount. Installation copies only bytes
  # authenticated by the externally rooted release manifest into the volume.
  /usr/local/bin/tron-release-verify install \
    --trust-store "$trust_store" \
    --manifest "$manifest" \
    --bundle "$bundle" \
    --platform P-LINUX-X64 \
    --channel "$channel" \
    --minimum-sequence "$minimum_sequence" \
    --prefix "$prefix" \
    --config-root /etc/tron \
    --receipt "$receipt" \
    --retained-slots "${TRON_RETAINED_RELEASES:-2}" \
    --verification-time "$verification_time"
fi
for directory in /var/lib/tron/data /var/lib/tron/keystore /var/lib/tron/snapshot-acceptance; do
  mkdir -p "$directory"
  chmod 0700 "$directory"
done


deployment_config=${TRON_DEPLOYMENT_CONFIG:-/etc/tron/current/$deployment}
chain_config=/etc/tron/current/${mode}.conf
test -r "$chain_config" || { echo "verified HOCON config is not readable: $chain_config" >&2; exit 66; }
test -r "$deployment_config" || { echo "verified deployment config is not readable: $deployment_config" >&2; exit 66; }

"$prefix/current/bin/$binary" preflight --deployment-config "$deployment_config" --json
exec "$prefix/current/bin/$binary" --deployment-config "$deployment_config" "$@"
