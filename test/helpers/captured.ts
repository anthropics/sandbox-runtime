export type Captured<T> = {
  value: T | undefined
  /** Forget the recorded value, so the next read is about the next request. */
  clear(): void
}

/**
 * A slot an upstream server's request handler records into and the test that
 * triggered the request reads back.
 *
 * A plain `let` does not type: the compiler cannot see a callback's write, so
 * a test that clears the variable before its request narrows it to
 * `undefined` for the rest of that test and every read afterwards is an error
 * on `never`. Clearing through a method leaves the declared type in place.
 */
export function captured<T>(): Captured<T> {
  return {
    value: undefined,
    clear() {
      this.value = undefined
    },
  }
}
