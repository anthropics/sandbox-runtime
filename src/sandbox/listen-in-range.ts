/**
 * Listen options for srt's loopback listeners.
 *
 * `exclusive` keeps the handle out of Node's cluster sharing. srt is a
 * one-process-one-proxy design — the mux backend binds a pid-scoped unix
 * socket and each process mints its own proxyAuthToken — but under `cluster`
 * a plain listen() is intercepted by the primary, which shares one handle
 * across workers and round robins connections. A sandboxed child of worker A
 * would then reach worker B's proxy carrying A's token and get a 407.
 */
export function loopbackListenOptions(port: number): {
  port: number
  host: string
  exclusive: true
} {
  return { port, host: '127.0.0.1', exclusive: true }
}

/**
 * Bind `server` to the first free port in `range`, retrying on EADDRINUSE.
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
        if (
          range &&
          (err as NodeJS.ErrnoException)?.code === 'EADDRINUSE' &&
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
