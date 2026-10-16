import { describe, expect, test } from 'bun:test'
import * as fs from 'node:fs'
import { getPackageVersion } from '../../src/utils/package-version.js'

describe('getPackageVersion', () => {
  test('matches the version field of the repository package.json', () => {
    const pkg = JSON.parse(
      fs.readFileSync(new URL('../../package.json', import.meta.url), 'utf-8'),
    ) as { version: string }
    expect(getPackageVersion()).toBe(pkg.version)
  })

  test('looks like a semver string, not the npm_package_version fallback', () => {
    expect(getPackageVersion()).toMatch(/^\d+\.\d+\.\d+/)
    expect(getPackageVersion()).not.toBe('1.0.0')
  })
})
