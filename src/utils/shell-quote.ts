/**
 * Shell-escape an array of arguments into a single string that, when parsed
 * by a POSIX shell (`sh -c`, `bash -c`, `zsh -c`), yields exactly the
 * original argument list.
 *
 * This intentionally replaces the npm `shell-quote` package. Its quote()
 * switches to a double-quote + backslash strategy whenever an argument
 * contains a single quote, and in that mode it backslash-escapes `!` — a
 * guard against history expansion that only applies to *interactive*
 * shells. Every string this library produces is executed through a
 * non-interactive `<shell> -c`, where bash treats `\!` inside double quotes
 * as two literal characters (the backslash is NOT removed). The wrapped
 * user command almost always contains a single quote, so every `!` in it
 * reached the program corrupted to `\!`: heredoc-written source like
 * `if (!x)` became unparseable, and `jq 'a != b'`, `awk '!seen[$0]++'`,
 * and `find ! -name` filters were silently rewritten.
 *
 * Single-quoting never has that problem. Inside POSIX single quotes every
 * byte is literal, so nothing needs escaping; the only character that
 * needs handling is the single quote itself, emitted as the standard
 * `'"'"'` sequence (close the quote, a double-quoted `'`, reopen).
 *
 * @param args - The argument list to escape
 * @returns A single space-joined string safe to pass to `<shell> -c`
 */
export function quote(args: readonly string[]): string {
  return args
    .map(arg => {
      if (arg === '') {
        return "''"
      }
      // Bare fast path: nothing in this character set is special to a
      // POSIX shell (no whitespace, globs, expansions, quotes, or
      // operators), so the bare word re-parses to exactly itself. The one
      // position-sensitive case is a LEADING "=": zsh (a common binShell,
      // even non-interactive `zsh -c`) performs "equals expansion" on an
      // unquoted word starting with "=" (`=ls` becomes /bin/ls; an unknown
      // name aborts the whole command line), so such a word must be quoted.
      // "=" elsewhere in the word (NAME=value env assignments) is fine.
      if (/^[A-Za-z0-9_./:@+,-][A-Za-z0-9_./:=@+,-]*$/.test(arg)) {
        return arg
      }
      return "'" + arg.replace(/'/g, `'"'"'`) + "'"
    })
    .join(' ')
}

// cmd.exe's metacharacters, each escaped with `^` so cmd passes it through
// literally. `"` is among them, so cmd never enters its own quote state and
// the quotes reach the program for its argv parser.
const CMD_META = /([()\][%!^"`<>&|;, *?])/g

/**
 * Escape an argument list into one command line for `cmd.exe /d /s /c`,
 * which is how the CLI runs a command on Windows. Each argument is quoted
 * for the program's own argv parser (the MSVCRT rules), then every cmd
 * metacharacter is caret-escaped. The program name is wrapped in plain
 * quotes instead, which is what cmd reads when it finds the executable.
 *
 * {@link quote}'s POSIX single quotes mean nothing to cmd, so they reached
 * the program as literal characters around any argument holding a `\`,
 * which is every absolute Windows path.
 *
 * @param args - The argument list to escape, the program first
 * @returns A single string that cmd runs as exactly that argument list
 */
export function quoteForCmd(args: readonly string[]): string {
  return args
    .map((arg, i) => {
      if (/^[A-Za-z0-9_./:\\@+-]+$/.test(arg)) {
        return arg
      }
      // cmd finds the executable before any argv parsing and honours plain
      // quotes there. Inside them it still expands `%` and ends the line at
      // a line break, and a `"` would close them, so a program name holding
      // any of those is refused rather than run as something else.
      if (i === 0) {
        if (/["%\r\n\0]/.test(arg)) {
          throw new Error(
            `cannot pass the program name ${JSON.stringify(arg)} to cmd.exe: ` +
              'it holds a ", %, or line break. Use -c to give the command line yourself.',
          )
        }
        return '"' + arg + '"'
      }
      // MSVCRT: backslashes are literal unless they precede a `"`, so double
      // the ones before an embedded quote and the ones before the closing one.
      const msvcrt =
        '"' + arg.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\*)$/, '$1$1') + '"'
      return msvcrt.replace(CMD_META, '^$1')
    })
    .join(' ')
}
