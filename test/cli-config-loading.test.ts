import { describe, it, expect, afterEach, beforeEach } from 'vitest'
import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import { loadConfig, loadConfigFromString } from '../src/utils/config-loader.js'

describe('loadConfig', () => {
  let tmpDir: string
  let configPath: string

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'config-test-'))
    configPath = path.join(tmpDir, 'config.json')
  })

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true })
  })

  // The caller has to tell a file that is not there — the one case that
  // may fall back to the built-in defaults — from one that is there and
  // did not load, so each of those gets its own kind.
  it('should report missing when the file does not exist', () => {
    const result = loadConfig('/nonexistent/path/config.json')
    expect(result).toEqual({ kind: 'missing' })
  })

  it('should report unreadable, not missing, when the path is a directory', () => {
    fs.mkdirSync(configPath)
    const result = loadConfig(configPath)
    expect(result.kind).toBe('unreadable')
    expect(result.kind === 'unreadable' && result.reason).toContain('EISDIR')
  })

  it('should report empty for an empty file', () => {
    fs.writeFileSync(configPath, '')
    expect(loadConfig(configPath)).toEqual({ kind: 'empty' })
  })

  it('should report empty for a whitespace-only file', () => {
    fs.writeFileSync(configPath, '   \n\t  ')
    expect(loadConfig(configPath)).toEqual({ kind: 'empty' })
  })

  it('should report invalid for invalid JSON', () => {
    fs.writeFileSync(configPath, '{ invalid json }')

    const result = loadConfig(configPath)

    expect(result.kind).toBe('invalid')
    expect(result.kind === 'invalid' && result.reason).toContain(
      'is not valid JSON',
    )
  })

  it('should report invalid and name the failing keys for a schema mismatch', () => {
    // Valid JSON but missing required fields
    fs.writeFileSync(configPath, JSON.stringify({ network: {} }))

    const result = loadConfig(configPath)

    expect(result.kind).toBe('invalid')
    expect(result.kind === 'invalid' && result.reason).toContain(
      'network.allowedDomains',
    )
  })

  it('should return valid config for valid file', () => {
    const validConfig = {
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    }
    fs.writeFileSync(configPath, JSON.stringify(validConfig))

    const result = loadConfig(configPath)

    expect(result.kind).toBe('ok')
    expect(
      result.kind === 'ok' && result.config.network.allowedDomains,
    ).toContain('example.com')
  })
})

describe('loadConfigFromString', () => {
  it('should return null for empty string', () => {
    const result = loadConfigFromString('')
    expect(result).toBeNull()
  })

  it('should return null for whitespace-only string', () => {
    const result = loadConfigFromString('   \n\t  ')
    expect(result).toBeNull()
  })

  it('should return null for invalid JSON', () => {
    const result = loadConfigFromString('{ invalid json }')
    expect(result).toBeNull()
  })

  it('should return null for valid JSON with invalid schema', () => {
    // Valid JSON but missing required fields
    const result = loadConfigFromString(JSON.stringify({ network: {} }))
    expect(result).toBeNull()
  })

  it('should return valid config for valid JSON', () => {
    const validConfig = {
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    }
    const result = loadConfigFromString(JSON.stringify(validConfig))

    expect(result).not.toBeNull()
    expect(result?.network.allowedDomains).toContain('example.com')
  })
})
