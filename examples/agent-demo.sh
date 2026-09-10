#!/usr/bin/env bash
# Reference agent for the Sandbox-Agent channel.
#
# Run it inside srt with the channel open:
#
#   srt --agent-channel -- ./examples/agent-demo.sh curl https://api.github.com
#   srt --agent-channel -- ./examples/agent-demo.sh          # interactive shell
#
# The script plays the "agent" role from the protocol: it completes the
# hello handshake on the file descriptor named by SANDBOX_AGENT_CHANNEL_FD,
# answers permission_request messages (prompting on the terminal, or
# automatically via SRT_AGENT_DEMO_BEHAVIOR=allow|deny), prints blocked
# notifications, and runs the given command — its "tools" — with the
# channel descriptors closed.
#
# Protocol (newline-delimited JSON, version 1):
#   sandbox → agent   hello, permission_request, blocked
#   agent → sandbox   hello, permission_response
#
# The JSON handling here is deliberately sed-grade: good enough for the
# messages srt emits, and easy to read as a protocol illustration. A real
# agent should use a real JSON parser.

set -u

fd="${SANDBOX_AGENT_CHANNEL_FD:?agent-demo must run under srt --agent-channel}"

# Duplicate the channel onto dedicated read/write descriptors, then close
# the original so the tool processes below don't inherit it under its
# advertised name. (The agent and its tools share one jail either way —
# this is hygiene, not isolation.)
exec 8<&"$fd" 9>&"$fd"
eval "exec $fd<&-"

send() {
  printf '%s\n' "$1" >&9
}

# Best-effort extraction of a string field from a one-line JSON object:
# leftmost occurrence of `"field":"value"`, so a nested `"type"` (e.g.
# inside `resource`) doesn't shadow the message's own. Pure bash on
# purpose — a subprocess per message would itself trip sandbox violations,
# and each violation becomes another message. Breaks on escaped quotes
# inside values; fine for a demo.
json_field() {
  local re="\"$2\"[[:space:]]*:[[:space:]]*\"([^\"]*)\""
  if [[ $1 =~ $re ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
  fi
}

decide() {
  # $1 = description. Echoes "allow" or "deny".
  case "${SRT_AGENT_DEMO_BEHAVIOR:-prompt}" in
    allow) echo allow ;;
    deny) echo deny ;;
    *)
      # `[ -r /dev/tty ]` is true even without a controlling terminal, so
      # test by actually opening it.
      if (exec </dev/tty) 2>/dev/null; then
        printf 'agent-demo: %s — allow? [y/N] ' "$1" >/dev/tty
        IFS= read -r answer </dev/tty || answer=
        case "$answer" in
          y | Y | yes | YES) echo allow ;;
          *) echo deny ;;
        esac
      else
        # No terminal to ask on: fail safe.
        echo deny
      fi
      ;;
  esac
}

# Finish the handshake. Until our hello arrives the sandbox asks nothing
# and denies whatever its policy does not cover.
send '{"type":"hello","protocol_version":1}'

# The agent loop: answer the sandbox while the tools run in the foreground.
(
  while IFS= read -r line <&8; do
    type=$(json_field "$line" type)
    case "$type" in
      hello) ;; # the sandbox's side of the handshake; nothing to do
      permission_request)
        id=$(json_field "$line" id)
        description=$(json_field "$line" description)
        behavior=$(decide "${description:-$line}")
        send '{"type":"permission_response","id":"'"$id"'","behavior":"'"$behavior"'"}'
        printf 'agent-demo: %s → %s\n' "${description:-$line}" "$behavior" >&2
        ;;
      blocked)
        description=$(json_field "$line" description)
        printf 'agent-demo: sandbox blocked an action: %s\n' "${description:-$line}" >&2
        ;;
      *) ;; # unknown message types are ignored, per protocol
    esac
  done
) &
agent_loop=$!

# Run the "tools" — the untrusted part of the trust boundary — with the
# channel descriptors closed.
if [ "$#" -gt 0 ]; then
  "$@" 8<&- 9>&-
else
  "${SHELL:-sh}" -i 8<&- 9>&-
fi
status=$?

kill "$agent_loop" 2>/dev/null
exit "$status"
