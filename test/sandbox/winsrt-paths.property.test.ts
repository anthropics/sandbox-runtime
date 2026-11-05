import { afterAll, beforeAll, describe, it } from 'bun:test'
import * as fc from 'fast-check'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  containsGlobCharsWin,
  stripExtendedPathPrefix,
} from '../../src/sandbox/sandbox-utils.js'
import { expandWindowsFsPaths } from '../../src/sandbox/windows-sandbox-utils.js'

/**
 * Property tests for the Windows path-normalisation pipeline.
 * Pins the case-fold and glob/literal-divergence invariants
 * generically (regression coverage for past bugs in this layer).
 * Pure-JS — runs on every CI leg.
 */

describe('property: stripExtendedPathPrefix', () => {
  it('UNC marker is case-fold-stable', () => {
    fc.assert(
      fc.property(
        fc.constantFrom('UNC', 'Unc', 'unc', 'uNc', 'uNC', 'UnC'),
        fc
          .string({ minLength: 1, maxLength: 40 })
          .filter(s => !s.startsWith('\\')),
        (casing, tail) => {
          const ref = stripExtendedPathPrefix(`\\\\?\\UNC\\${tail}`)
          const got = stripExtendedPathPrefix(`\\\\?\\${casing}\\${tail}`)
          return got === ref && got === `\\\\${tail}`
        },
      ),
    )
  })

  it('non-UNC `\\\\?\\` strip is invariant in the residue', () => {
    fc.assert(
      fc.property(
        fc.constantFrom('C', 'c', 'D', 'z'),
        fc.string({ minLength: 0, maxLength: 40 }),
        (drive, tail) => {
          const p = `\\\\?\\${drive}:\\${tail}`
          return stripExtendedPathPrefix(p) === `${drive}:\\${tail}`
        },
      ),
    )
  })
})

describe('property: containsGlobCharsWin', () => {
  it('true ⇔ contains `*` or `?`', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 60 }), s => {
        const want = s.includes('*') || s.includes('?')
        return containsGlobCharsWin(s) === want
      }),
    )
  })
})

describe('property: expandWindowsFsPaths', () => {
  let scratch: string
  const files: string[] = []

  beforeAll(() => {
    scratch = mkdtempSync(join(tmpdir(), 'srt-prop-'))
    for (let i = 0; i < 5; i++) {
      const f = join(scratch, `f${i}.txt`)
      writeFileSync(f, String(i))
      files.push(f)
    }
    // Patterns belong in the swept corpus: without one, every sample takes
    // the literal branch and the glob branch is never reached.
    files.push(join(scratch, 'f*.txt'), join(scratch, 'f?.txt'))
  })

  afterAll(() => {
    rmSync(scratch, { recursive: true, force: true })
  })

  it('idempotent: f(f(xs)) == f(xs)', () => {
    // Catches normalize-divergence between the literal and glob
    // branches generically — feeding the output back in must
    // round-trip.
    fc.assert(
      fc.property(fc.subarray(files, { minLength: 1 }), subset => {
        const once = expandWindowsFsPaths(subset)
        const twice = expandWindowsFsPaths(once)
        return (
          once.length === twice.length &&
          new Set(once).size === once.length &&
          once.every(p => twice.includes(p))
        )
      }),
    )
  })
})
