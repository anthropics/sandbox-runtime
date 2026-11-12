# CLI invocation modes

The `srt` CLI treats positional arguments as argv-style input. Pass the executable and its arguments as separate shell arguments:

```bash
srt curl https://example.com
srt cat README.md
srt echo "hello world"
```

Do not quote an entire command as one positional argument:

```bash
# Incorrect in argv mode: this is one argument whose value is `cat README.md`
srt "cat README.md"
```

When the command intentionally relies on shell syntax such as pipes, redirections, `&&`, or variable expansion, use `-c` to pass a complete shell command string:

```bash
srt -c 'cat README.md | grep sandbox'
srt -c 'npm install && npm test'
srt -c 'echo "$HOME" > home.txt'
```

This distinction matters because argv-style invocation preserves argument boundaries. A quoted whole command such as `srt "cat README.md"` is therefore treated as a single command argument rather than being split into `cat` and `README.md`.
