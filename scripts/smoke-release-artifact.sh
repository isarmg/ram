#!/usr/bin/env bash
set -Eeuo pipefail

readonly HEALTH_BODY='{"status":"OK"}'
readonly SMOKE_USER='release-smoke'
readonly SMOKE_PASSWORD='release-smoke-password'
readonly MAX_RELEASE_GLIBC_VERSION='2.39'
readonly MAX_RELEASE_ARCHIVE_BYTES=$((64 * 1024 * 1024))

usage() {
  cat <<'EOF'
Usage:
  scripts/smoke-release-artifact.sh --check-prerequisites
  scripts/smoke-release-artifact.sh \
    <archive.tar.gz> <expected-target> <expected-ELF-machine> \
    <expected-source-commit> <diagnostics-directory>

The full smoke test verifies the archive checksum, extracts the archive into a
private temporary directory, and runs only the extracted `ram` binary. The
diagnostics directory receives public test responses, server logs, and archive
and binary hashes. Authentication files and TLS private keys remain in the
private temporary directory and are always deleted.
EOF
}

required_commands=(
  awk
  basename
  cat
  chmod
  cmp
  cp
  curl
  dirname
  find
  grep
  gzip
  kill
  ldd
  mkdir
  mktemp
  openssl
  python3
  readelf
  realpath
  rm
  sed
  sha256sum
  sleep
  sort
  stat
  tail
  tar
  timeout
  uname
)

check_prerequisites() {
  local missing=()
  local command_name
  for command_name in "${required_commands[@]}"; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
      missing+=("$command_name")
    fi
  done
  if (( ${#missing[@]} != 0 )); then
    printf 'Missing release-smoke prerequisites: %s\n' "${missing[*]}" >&2
    return 1
  fi

  if ! curl --version | grep -Eq '^Features:.*[[:space:]]HTTP2([[:space:]]|$)'; then
    echo 'curl lacks HTTP2 support; refusing to weaken the release artifact smoke test' >&2
    return 1
  fi
}

if (( $# == 1 )) && [[ $1 == "--check-prerequisites" ]]; then
  check_prerequisites
  echo 'release artifact smoke prerequisites are available (including curl HTTP2)'
  exit 0
fi

if (( $# != 5 )); then
  usage >&2
  exit 2
fi

archive_input=$1
expected_target=$2
expected_machine=$3
expected_source_commit=$4
diagnostics_input=$5

if [[ -e $diagnostics_input ]] &&
  [[ -n $(find "$diagnostics_input" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null) ]]; then
  echo "Diagnostics directory must be empty: $diagnostics_input" >&2
  exit 1
fi
mkdir -p -- "$diagnostics_input"
diagnostics=$(realpath -- "$diagnostics_input")
printf 'status=running\ntarget=%s\nexpected_machine=%s\n' \
  "$expected_target" "$expected_machine" >"$diagnostics/summary.txt"

early_fail() {
  printf 'Release artifact smoke failed: %s\n' "$*" >&2
  printf 'failure=%s\nstatus=failed\nexit_status=1\n' "$*" \
    >>"$diagnostics/summary.txt"
  exit 1
}

if ! check_prerequisites >"$diagnostics/prerequisites.txt" 2>&1; then
  early_fail 'required release-smoke tools are unavailable or curl lacks HTTP2'
fi

if [[ ! -f $archive_input ]]; then
  early_fail "release archive does not exist: $archive_input"
fi

archive=$(realpath -- "$archive_input")
archive_size=$(stat --format='%s' -- "$archive")
if (( archive_size > MAX_RELEASE_ARCHIVE_BYTES )); then
  early_fail "release archive is $archive_size bytes; limit is $MAX_RELEASE_ARCHIVE_BYTES"
fi
sha256sum "$archive" >"$diagnostics/archive.sha256.actual"
checksum_file="${archive}.sha256"
if [[ ! -f $checksum_file ]]; then
  early_fail "release archive checksum does not exist: $checksum_file"
fi

workdir=$(mktemp -d "${TMPDIR:-/tmp}/ram-release-smoke.XXXXXX")
server_pid=
SERVER_PORT=

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  set +e
  if [[ -n $server_pid ]]; then
    if kill -0 "$server_pid" 2>/dev/null; then
      kill -TERM "$server_pid" 2>/dev/null
      if ! timeout 3s tail --pid="$server_pid" -f /dev/null >/dev/null 2>&1; then
        kill -KILL "$server_pid" 2>/dev/null
      fi
    fi
    wait "$server_pid" 2>/dev/null
  fi
  rm -rf -- "$workdir"
  if (( status != 0 )); then
    printf 'status=failed\nexit_status=%s\n' "$status" >>"$diagnostics/summary.txt"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
  printf 'Release artifact smoke failed: %s\n' "$*" >&2
  printf 'failure=%s\n' "$*" >>"$diagnostics/summary.txt"
  exit 1
}

record_tool_versions() {
  {
    printf 'uname: '
    uname -a
    printf 'curl:\n'
    curl --version
    printf 'openssl: '
    openssl version
    printf 'python: '
    python3 --version
    printf 'readelf: '
    readelf --version | sed -n '1p'
    printf 'tar: '
    tar --version | sed -n '1p'
  } >"$diagnostics/tool-versions.txt" 2>&1
}

header_value() {
  local header_name=${1,,}
  local header_file=$2
  awk -v wanted="$header_name" '
    {
      line = $0
      sub(/\r$/, "", line)
      separator = index(line, ":")
      if (separator > 0 && tolower(substr(line, 1, separator - 1)) == wanted) {
        value = substr(line, separator + 1)
        sub(/^[ \t]*/, "", value)
        print value
        exit
      }
    }
  ' "$header_file"
}

assert_header() {
  local header_name=$1
  local expected_value=$2
  local header_file=$3
  local actual_value
  actual_value=$(header_value "$header_name" "$header_file")
  if [[ $actual_value != "$expected_value" ]]; then
    fail "expected $header_name '$expected_value', got '${actual_value:-<missing>}'"
  fi
}

LAST_BODY=
LAST_HEADERS=
LAST_STATUS=
LAST_HTTP_VERSION=

http_request() {
  local label=$1
  local expected_status=$2
  shift 2

  LAST_BODY="$diagnostics/${label}.body"
  LAST_HEADERS="$diagnostics/${label}.headers"
  local curl_stderr="$diagnostics/${label}.curl.stderr"
  local metrics
  local curl_status
  if metrics=$(curl \
    --silent \
    --show-error \
    --noproxy '*' \
    --connect-timeout 2 \
    --max-time 15 \
    --dump-header "$LAST_HEADERS" \
    --output "$LAST_BODY" \
    --write-out $'%{http_code}\t%{http_version}' \
    "$@" 2>"$curl_stderr"); then
    curl_status=0
  else
    curl_status=$?
  fi

  IFS=$'\t' read -r LAST_STATUS LAST_HTTP_VERSION <<<"$metrics"
  printf 'curl_exit=%s\nexpected_status=%s\nactual_status=%s\nhttp_version=%s\n' \
    "$curl_status" "$expected_status" "${LAST_STATUS:-<missing>}" \
    "${LAST_HTTP_VERSION:-<missing>}" >"$diagnostics/${label}.status"

  if (( curl_status != 0 )); then
    fail "$label curl failed with exit status $curl_status"
  fi
  if [[ $LAST_STATUS != "$expected_status" ]]; then
    fail "$label expected HTTP $expected_status, got ${LAST_STATUS:-<missing>}"
  fi
}

allocate_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

start_server() {
  local phase=$1
  shift
  local port
  port=$(allocate_port)
  SERVER_PORT=$port
  server_pid=
  env -u RAM_CONFIG "$binary" "$data_dir" \
    --bind 127.0.0.1 \
    --port "$port" \
    --auth-file "$auth_file" \
    --allow-upload \
    --allow-delete \
    "$@" >"$diagnostics/${phase}-server.log" 2>&1 &
  server_pid=$!
}

wait_ready() {
  local phase=$1
  local health_url=$2
  shift 2
  local readiness_body="$workdir/${phase}-readiness.body"
  local status
  local attempt

  for ((attempt = 1; attempt <= 100; attempt += 1)); do
    if ! kill -0 "$server_pid" 2>/dev/null; then
      local exit_status
      if wait "$server_pid"; then
        exit_status=0
      else
        exit_status=$?
      fi
      server_pid=
      fail "$phase server exited before readiness with status $exit_status"
    fi

    if grep -q 'Listening on' "$diagnostics/${phase}-server.log" 2>/dev/null; then
      status=$(curl \
        --silent \
        --show-error \
        --noproxy '*' \
        --connect-timeout 1 \
        --max-time 2 \
        --output "$readiness_body" \
        --write-out '%{http_code}' \
        "$@" "$health_url" 2>/dev/null || true)
      if [[ $status == 200 ]] && [[ $(<"$readiness_body") == "$HEALTH_BODY" ]]; then
        return
      fi
    fi
    sleep 0.1
  done

  fail "$phase server did not become ready within 10 seconds"
}

stop_server() {
  local phase=$1
  local pid=$server_pid
  local exit_status
  if [[ -z $pid ]]; then
    fail "$phase server has no recorded process"
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    if wait "$pid"; then
      exit_status=0
    else
      exit_status=$?
    fi
    server_pid=
    fail "$phase server exited before SIGTERM with status $exit_status"
  fi

  kill -TERM "$pid"
  if ! timeout 15s tail --pid="$pid" -f /dev/null >/dev/null 2>&1; then
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    server_pid=
    printf 'exit_status=timeout\n' >"$diagnostics/${phase}-shutdown.txt"
    fail "$phase server did not exit within 15 seconds of SIGTERM"
  fi

  if wait "$pid"; then
    exit_status=0
  else
    exit_status=$?
  fi
  server_pid=
  printf 'exit_status=%s\n' "$exit_status" >"$diagnostics/${phase}-shutdown.txt"
  if (( exit_status != 0 )); then
    fail "$phase server returned $exit_status after SIGTERM"
  fi
}

record_tool_versions

cp -- "$checksum_file" "$diagnostics/archive.sha256.expected"
if ! python3 scripts/check-release-assets.py checksum "$archive" "$checksum_file" \
  >"$diagnostics/archive-check.txt" 2>&1; then
  fail 'archive checksum verification failed'
fi

archive_filename=$(basename -- "$archive")
if [[ $archive_filename != *.tar.gz ]]; then
  fail "archive must end in .tar.gz: $archive_filename"
fi
stage_name=${archive_filename%.tar.gz}
if [[ $stage_name != *-"$expected_target" ]]; then
  fail "archive name '$stage_name' does not end in expected target '$expected_target'"
fi
version_name=${stage_name%-$expected_target}
if [[ $version_name != ram-v* ]] ||
  [[ ! $version_name =~ ^ram-v([0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?)$ ]]; then
  fail "archive name '$stage_name' does not contain a valid release version"
fi
expected_version=${BASH_REMATCH[1]}

# 解压前验证名称和条目类型。精确允许列表使打包变更必须有意进行，并在生产任务被修改时仍阻止
# 绝对路径、遍历、重复成员、链接、设备或误打包秘密进入发布。
# Validate names/types before extraction. The exact allowlist makes packaging changes deliberate and
# keeps absolute/traversal/duplicate/link/device/secret entries out even if the producer changes.
if ! python3 scripts/check-release-archive.py verify "$archive" "$stage_name" \
  >"$diagnostics/archive-policy.txt" 2>&1; then
  fail 'release archive failed the exact path and entry-type policy'
fi

# 仅在流式策略限制每个成员和总展开大小后生成可读列表；先列出未检查 gzip 本身就会允许解压 CPU 炸弹。
# Produce the human-readable listing only after streaming policy bounds each member and aggregate
# expansion. Listing an unchecked gzip first would itself permit a decompression CPU bomb.
if ! tar --list --verbose --gzip --file "$archive" \
  >"$diagnostics/archive-contents.txt" 2>&1; then
  fail 'archive listing failed'
fi

extract_dir="$workdir/extracted"
mkdir -p -- "$extract_dir"
if ! tar --extract --gzip --no-same-owner --file "$archive" --directory "$extract_dir"; then
  fail 'archive extraction failed'
fi
binary="$extract_dir/$stage_name/ram"
if [[ ! -f $binary ]] || [[ -L $binary ]] || [[ ! -x $binary ]]; then
  fail 'archive ram entry is not a regular executable file'
fi
if [[ $(stat --format='%a' -- "$binary") != 755 ]]; then
  fail "archive ram mode is not 0755"
fi

manifest="$extract_dir/$stage_name/$stage_name.supply-chain.json"
if ! python3 scripts/check-release-manifest.py verify \
  --version "$expected_version" \
  --target "$expected_target" \
  --repository 'https://github.com/isarmg/ram' \
  --commit "$expected_source_commit" \
  --binary "$binary" \
  --cyclonedx "$extract_dir/$stage_name/ram-fileserver-${expected_target}.cdx.json" \
  --spdx "$extract_dir/$stage_name/ram-fileserver.spdx.json" \
  --manifest "$manifest" >"$diagnostics/supply-chain-manifest.txt" 2>&1; then
  fail 'release supply-chain manifest does not bind this binary and target SBOM'
fi

sha256sum "$binary" >"$diagnostics/binary.sha256"
if command -v file >/dev/null 2>&1; then
  file "$binary" >"$diagnostics/binary.file.txt"
else
  echo 'file utility unavailable; readelf diagnostics remain authoritative' \
    >"$diagnostics/binary.file.txt"
fi
readelf --file-header "$binary" >"$diagnostics/binary.readelf-header.txt"
readelf --notes "$binary" >"$diagnostics/binary.readelf-notes.txt"
readelf --wide --program-headers "$binary" >"$diagnostics/binary.readelf-program-headers.txt"
readelf --dynamic "$binary" >"$diagnostics/binary.readelf-dynamic.txt"
readelf --version-info "$binary" >"$diagnostics/binary.readelf-version-info.txt"
if ! ldd "$binary" >"$diagnostics/binary.ldd.txt" 2>&1; then
  fail 'ldd could not resolve the release binary'
fi
if grep -Fq 'not found' "$diagnostics/binary.ldd.txt"; then
  fail 'the release binary has an unresolved dynamic library'
fi

actual_machine=$(awk -F: '
  /^[[:space:]]*Machine:/ {
    sub(/^[[:space:]]+/, "", $2)
    print $2
  }
' "$diagnostics/binary.readelf-header.txt")
if [[ $actual_machine != "$expected_machine" ]]; then
  fail "expected ELF machine '$expected_machine', got '$actual_machine'"
fi

actual_type=$(awk -F: '
  /^[[:space:]]*Type:/ {
    sub(/^[[:space:]]+/, "", $2)
    print $2
  }
' "$diagnostics/binary.readelf-header.txt")
if [[ $actual_type != DYN* ]]; then
  fail "release binary is not PIE (ELF type is '$actual_type')"
fi
if ! grep -q 'GNU_RELRO' "$diagnostics/binary.readelf-program-headers.txt"; then
  fail 'release binary has no GNU_RELRO segment'
fi
stack_line=$(grep 'GNU_STACK' "$diagnostics/binary.readelf-program-headers.txt" || true)
if [[ -z $stack_line ]] || [[ $stack_line =~ GNU_STACK.*E ]]; then
  fail 'release binary has a missing or executable GNU_STACK policy'
fi
if ! grep -Eq 'BIND_NOW|Flags:.*NOW' "$diagnostics/binary.readelf-dynamic.txt"; then
  fail 'release binary does not enable immediate binding/full RELRO'
fi
if grep -Eq '\((RPATH|RUNPATH|TEXTREL)\)|Flags:.*TEXTREL' \
  "$diagnostics/binary.readelf-dynamic.txt"; then
  fail 'release binary contains RPATH, RUNPATH, or text relocations'
fi
if ! grep -Eq 'Build ID: [0-9a-fA-F]+' "$diagnostics/binary.readelf-notes.txt"; then
  fail 'release binary has no ELF build ID'
fi

mapfile -t needed_libraries < <(
  sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' \
    "$diagnostics/binary.readelf-dynamic.txt"
)
if (( ${#needed_libraries[@]} == 0 )); then
  fail 'release binary did not declare any dynamic libraries'
fi
for library in "${needed_libraries[@]}"; do
  case "$library" in
    libc.so.6 | libdl.so.2 | libgcc_s.so.1 | libm.so.6 | libpthread.so.0 | \
      librt.so.1 | ld-linux-x86-64.so.2 | ld-linux-aarch64.so.1)
      ;;
    *)
      fail "release binary introduced an unreviewed dynamic library: $library"
      ;;
  esac
done

highest_glibc_version=$(
  # 中文：grep 的“无匹配”必须交给下方可读诊断；不能让 errexit 在赋值处
  # 提前退出并只留下一个无上下文状态码。
  # English: Let the explicit diagnostic below handle grep's no-match result;
  # errexit must not terminate at the assignment with only a context-free status.
  { grep -Eo 'GLIBC_[0-9]+(\.[0-9]+)+' \
    "$diagnostics/binary.readelf-version-info.txt" || true; } |
    sed 's/^GLIBC_//' |
    sort -Vu |
    tail -n 1
)
if [[ -z $highest_glibc_version ]]; then
  fail 'release binary did not expose a reviewable GLIBC symbol baseline'
fi
if [[ $(printf '%s\n%s\n' "$MAX_RELEASE_GLIBC_VERSION" "$highest_glibc_version" |
  sort -V | tail -n 1) != "$MAX_RELEASE_GLIBC_VERSION" ]]; then
  fail "release binary requires GLIBC_$highest_glibc_version, above documented GLIBC_$MAX_RELEASE_GLIBC_VERSION"
fi

case "$expected_target" in
  x86_64-unknown-linux-gnu)
    expected_host=x86_64
    ;;
  aarch64-unknown-linux-gnu)
    expected_host=aarch64
    ;;
  *)
    fail "unsupported native release-smoke target: $expected_target"
    ;;
esac
actual_host=$(uname -m)
if [[ $actual_host != "$expected_host" ]]; then
  fail "release smoke must run natively on $expected_host, got $actual_host"
fi

if ! "$binary" --version >"$diagnostics/binary.version.txt" 2>&1; then
  fail 'release binary --version failed'
fi
actual_version=$(<"$diagnostics/binary.version.txt")
if [[ $actual_version != "ram $expected_version" ]]; then
  fail "release binary version '$actual_version' does not match archive version 'ram $expected_version'"
fi

data_dir="$workdir/data"
secrets_dir="$workdir/secrets"
mkdir -p -- "$data_dir" "$secrets_dir"
chmod 700 "$data_dir" "$secrets_dir"
sample_file="$workdir/sample.expected"
mutable_original="$workdir/mutable-original.expected"
mutable_replacement="$workdir/mutable-replacement.expected"
printf '0123456789abcdef\n' >"$sample_file"
printf 'created by release smoke\n' >"$mutable_original"
printf 'replaced by matching etag\n' >"$mutable_replacement"
cp -- "$sample_file" "$data_dir/sample.txt"

auth_file="$secrets_dir/ram.auth"
curl_auth_file="$secrets_dir/curl-auth.conf"
(
  umask 077
  printf '%s:%s@/:rw\n' "$SMOKE_USER" "$SMOKE_PASSWORD" >"$auth_file"
  printf 'user = "%s:%s"\n' "$SMOKE_USER" "$SMOKE_PASSWORD" >"$curl_auth_file"
)
chmod 600 "$auth_file" "$curl_auth_file"

start_server cleartext
clear_port=$SERVER_PORT
clear_base="http://127.0.0.1:$clear_port"
wait_ready cleartext "$clear_base/__ram__/health"

health_expected="$workdir/health.expected"
printf '%s' "$HEALTH_BODY" >"$health_expected"
http_request clear-health 200 "$clear_base/__ram__/health"
cmp -- "$health_expected" "$LAST_BODY" || fail 'health response body did not match'
assert_header cache-control no-store "$LAST_HEADERS"

http_request clear-basic-get 200 \
  --basic --config "$curl_auth_file" "$clear_base/sample.txt"
cmp -- "$sample_file" "$LAST_BODY" || fail 'Basic GET body did not match'

http_request clear-digest-get 200 \
  --digest --config "$curl_auth_file" "$clear_base/sample.txt"
cmp -- "$sample_file" "$LAST_BODY" || fail 'Digest GET body did not match'
if ! grep -Eq '^HTTP/1\.[01] 401([[:space:]]|$)' "$LAST_HEADERS"; then
  fail 'Digest exchange did not include an HTTP 401 challenge'
fi
if ! grep -Eiq '^www-authenticate:[[:space:]]*Digest .*algorithm=SHA-256' "$LAST_HEADERS"; then
  fail 'Digest exchange did not advertise SHA-256'
fi

range_expected="$workdir/range.expected"
printf '2345' >"$range_expected"
http_request clear-range 206 \
  --basic --config "$curl_auth_file" \
  --header 'Range: bytes=2-5' "$clear_base/sample.txt"
cmp -- "$range_expected" "$LAST_BODY" || fail 'Range body did not match bytes 2-5'
assert_header content-range 'bytes 2-5/17' "$LAST_HEADERS"
assert_header accept-ranges bytes "$LAST_HEADERS"

http_request clear-cache-source 200 \
  --basic --config "$curl_auth_file" "$clear_base/sample.txt"
etag=$(header_value etag "$LAST_HEADERS")
if [[ -z $etag ]] || [[ $etag == W/* ]] || [[ $etag != \"*\" ]]; then
  fail "expected a strong quoted ETag, got '${etag:-<missing>}'"
fi
http_request clear-cache-304 304 \
  --basic --config "$curl_auth_file" \
  --header "If-None-Match: $etag" "$clear_base/sample.txt"
if [[ -s $LAST_BODY ]]; then
  fail '304 response unexpectedly contained a body'
fi
assert_header etag "$etag" "$LAST_HEADERS"

http_request clear-put-create 201 \
  --basic --config "$curl_auth_file" \
  --request PUT --data-binary "@$mutable_original" "$clear_base/mutable.txt"
http_request clear-put-created-get 200 \
  --basic --config "$curl_auth_file" "$clear_base/mutable.txt"
cmp -- "$mutable_original" "$LAST_BODY" || fail 'created PUT body did not match'
mutable_etag=$(header_value etag "$LAST_HEADERS")
if [[ -z $mutable_etag ]] || [[ $mutable_etag == W/* ]] || [[ $mutable_etag != \"*\" ]]; then
  fail "expected a strong mutable-file ETag, got '${mutable_etag:-<missing>}'"
fi

http_request clear-put-stale 412 \
  --basic --config "$curl_auth_file" \
  --request PUT \
  --header 'If-Match: "ram-release-smoke-stale"' \
  --data-binary "@$mutable_replacement" "$clear_base/mutable.txt"
http_request clear-put-after-stale 200 \
  --basic --config "$curl_auth_file" "$clear_base/mutable.txt"
cmp -- "$mutable_original" "$LAST_BODY" || fail 'stale If-Match changed the file'

http_request clear-put-current 204 \
  --basic --config "$curl_auth_file" \
  --request PUT \
  --header "If-Match: $mutable_etag" \
  --data-binary "@$mutable_replacement" "$clear_base/mutable.txt"
http_request clear-put-after-current 200 \
  --basic --config "$curl_auth_file" "$clear_base/mutable.txt"
cmp -- "$mutable_replacement" "$LAST_BODY" || fail 'matching If-Match did not replace the file'

http_request clear-delete 204 \
  --basic --config "$curl_auth_file" \
  --request DELETE "$clear_base/mutable.txt"
http_request clear-delete-get 404 \
  --basic --config "$curl_auth_file" "$clear_base/mutable.txt"
stop_server cleartext

tls_cert="$secrets_dir/tls-cert.pem"
tls_key="$secrets_dir/tls-key.pem"
if ! (
  umask 077
  openssl req \
    -x509 \
    -newkey rsa:2048 \
    -sha256 \
    -nodes \
    -days 1 \
    -subj '/CN=localhost' \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign' \
    -keyout "$tls_key" \
    -out "$tls_cert"
) >"$diagnostics/tls-certificate-generation.log" 2>&1; then
  fail 'failed to generate temporary TLS identity'
fi
chmod 600 "$tls_key"
openssl x509 -in "$tls_cert" -noout -subject -issuer -dates -fingerprint -sha256 \
  >"$diagnostics/tls-certificate.txt"

start_server tls --tls-cert "$tls_cert" --tls-key "$tls_key"
tls_port=$SERVER_PORT
tls_base="https://localhost:$tls_port"
tls_curl_args=(
  --cacert "$tls_cert"
  --resolve "localhost:$tls_port:127.0.0.1"
)
wait_ready tls "$tls_base/__ram__/health" "${tls_curl_args[@]}"

if ! timeout 10s openssl s_client \
  -connect "127.0.0.1:$tls_port" \
  -servername localhost \
  -CAfile "$tls_cert" \
  -verify_return_error \
  -alpn 'h2,http/1.1' \
  </dev/null >"$diagnostics/tls-alpn.txt" 2>&1; then
  fail 'TLS handshake or certificate verification failed'
fi
if ! grep -q '^ALPN protocol: h2$' "$diagnostics/tls-alpn.txt"; then
  fail 'TLS server did not negotiate h2 through ALPN'
fi

http_request tls-h2-basic-get 200 \
  --http2 \
  "${tls_curl_args[@]}" \
  --basic --config "$curl_auth_file" "$tls_base/sample.txt"
if [[ $LAST_HTTP_VERSION != 2 ]] && [[ $LAST_HTTP_VERSION != 2.0 ]]; then
  fail "TLS GET did not use HTTP/2 (curl reported $LAST_HTTP_VERSION)"
fi
cmp -- "$sample_file" "$LAST_BODY" || fail 'TLS HTTP/2 GET body did not match'
stop_server tls

printf 'status=passed\n' >>"$diagnostics/summary.txt"
echo "release artifact smoke passed: $stage_name ($expected_machine)"
