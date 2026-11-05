/**
 * Bind `server` to the first free port in `range`, retrying on EADDRINUSE or
 * EACCES (Windows can report an occupied port as permission denied).
 * With `range` undefined, binds to ephemeral port 0 once. The Windows WFP
 * loopback permit is installed by range, so proxy listeners on Windows must
 * land inside it; other platforms bake the actual ephemeral port into the
 * sandbox profile and pass `range = undefined`.
 */
export function listenInRange(
  server: {
    once(ev: 'error' | 'listening', cb: (e?: Error) => void): unknown
    removeListener(ev: 'error' | 'listening', cb: (e?: Error) => void): unknown
  },
  doListen: (port: number) => void,
  range: readonly [number, number] | undefined,
  exclude: ReadonlySet<number>,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const [lo, hi] = range ?? [0, 0]
    let port = lo
    const tryNext = (): void => {
      while (exclude.has(port) && port <= hi) port++
      if (port > hi) {
        reject(
          new Error(
            `No free port in range ${lo}-${hi} (excluding ${[...exclude].join(',')})`,
          ),
        )
        return
      }
      const onListening = (): void => {
        server.removeListener('error', onError)
        resolve()
      }
      const onError = (err?: Error): void => {
        // The paired 'listening' once-listener never fired; drop it
        // so retries don't accumulate stale listeners.
        server.removeListener('listening', onListening)
        const code = (err as NodeJS.ErrnoException)?.code
        if (
          range &&
          (code === 'EADDRINUSE' || code === 'EACCES') &&
          port < hi
        ) {
          port++
          tryNext()
          return
        }
        reject(err ?? new Error('listen error'))
      }
      server.once('error', onError)
      server.once('listening', onListening)
      doListen(range ? port : 0)
    }
    tryNext()
  })
}
