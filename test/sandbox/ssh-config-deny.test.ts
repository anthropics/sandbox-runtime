import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import { mkdirSync, writeFileSync, rmSync, realpathSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  collectSshKeyDenyPaths,
  expandSshPathTokens,
  splitSshConfigLine,
} from '../../src/sandbox/ssh-config-deny.js'

/**
 * Resolve symlinks the way collectSshKeyDenyPaths does (macOS tmpdir is
 * /var -> /private/var), so expected paths compare equal to returned paths.
 */
function realPath(p: string): string {
  try {
    return realpathSync(p)
  } catch {
    return p
  }
}

describe('collectSshKeyDenyPaths', () => {
  let rawHome: string
  let home: string
  let sshDir: string

  beforeEach(() => {
    rawHome = join(
      tmpdir(),
      `ssh-deny-test-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    )
    sshDir = join(rawHome, '.ssh')
    mkdirSync(sshDir, { recursive: true })
    home = realPath(rawHome)
  })

  afterEach(() => {
    rmSync(rawHome, { recursive: true, force: true })
  })

  it('collects an IdentityFile living outside ~/.ssh', () => {
    const keyDir = join(rawHome, 'keys')
    mkdirSync(keyDir)
    writeFileSync(join(keyDir, 'work_ed25519'), 'private key')
    writeFileSync(
      join(sshDir, 'config'),
      `Host work\n  IdentityFile ${join(rawHome, 'keys', 'work_ed25519')}\n`,
    )

    const result = collectSshKeyDenyPaths(rawHome)
    expect(result).toContain(join(home, 'keys', 'work_ed25519'))
  })

  it('expands ~ and %d in IdentityFile arguments', () => {
    writeFileSync(join(rawHome, 'tilde_key'), 'k')
    writeFileSync(join(rawHome, 'percent_key'), 'k')
    writeFileSync(
      join(sshDir, 'config'),
      'IdentityFile ~/tilde_key\nIdentityFile %d/percent_key\n',
    )

    const result = collectSshKeyDenyPaths(rawHome)
    expect(result).toContain(join(home, 'tilde_key'))
    expect(result).toContain(join(home, 'percent_key'))
  })

  it('collects CertificateFile and ControlPath arguments', () => {
    writeFileSync(join(rawHome, 'cert.pub'), 'cert')
    writeFileSync(join(rawHome, 'mux'), '')
    writeFileSync(
      join(sshDir, 'config'),
      `CertificateFile ${join(rawHome, 'cert.pub')}\nControlPath ${join(rawHome, 'mux')}\n`,
    )

    const result = collectSshKeyDenyPaths(rawHome)
    expect(result).toContain(join(home, 'cert.pub'))
    expect(result).toContain(join(home, 'mux'))
  })

  it('follows Include directives recursively', () => {
    writeFileSync(join(rawHome, 'nested_key'), 'k')
    writeFileSync(join(sshDir, 'config'), 'Include level1\n')
    writeFileSync(join(sshDir, 'level1'), 'Include level2\n')
    writeFileSync(
      join(sshDir, 'level2'),
      `IdentityFile ${join(rawHome, 'nested_key')}\n`,
    )

    const result = collectSshKeyDenyPaths(rawHome)
    expect(result).toContain(join(home, 'nested_key'))
  })

  it('expands glob Include patterns relative to ~/.ssh', () => {
    writeFileSync(join(rawHome, 'glob_key_a'), 'k')
    writeFileSync(join(rawHome, 'glob_key_b'), 'k')
    mkdirSync(join(sshDir, 'config.d'))
    writeFileSync(
      join(sshDir, 'config.d', 'a.conf'),
      `IdentityFile ${join(rawHome, 'glob_key_a')}\n`,
    )
    writeFileSync(
      join(sshDir, 'config.d', 'b.conf'),
      `IdentityFile ${join(rawHome, 'glob_key_b')}\n`,
    )
    writeFileSync(join(sshDir, 'config'), 'Include config.d/*\n')

    const result = collectSshKeyDenyPaths(rawHome)
    expect(result).toContain(join(home, 'glob_key_a'))
    expect(result).toContain(join(home, 'glob_key_b'))
  })

  it('skips entries with connection-scoped %-tokens', () => {
    // %h depends on the host being connected to — unknowable at
    // config-assembly time, so the entry must be skipped, not guessed.
    writeFileSync(join(rawHome, 'real_key'), 'k')
    writeFileSync(
      join(sshDir, 'config'),
      `IdentityFile ${join(rawHome, '%h_key')}\nIdentityFile ${join(rawHome, 'real_key')}\n`,
    )

    const result = collectSshKeyDenyPaths(rawHome)
    expect(result).toContain(join(home, 'real_key'))
    expect(result.some(p => p.includes('%'))).toBe(false)
  })

  it('returns every default key name whether or not it exists yet', () => {
    // Denies must be in place BEFORE the secret exists (a key can be
    // generated mid-session); the backends tolerate absent entries.
    // An existing key realpaths (home); an absent one keeps the raw
    // spelling — both are denied.
    writeFileSync(join(sshDir, 'id_ed25519'), 'k')

    const result = collectSshKeyDenyPaths(rawHome)
    expect(result).toContain(join(home, '.ssh', 'id_ed25519'))
    expect(result).toContain(join(rawHome, '.ssh', 'id_rsa'))
  })

  it('returns nothing when no .ssh directory exists at all', () => {
    // No .ssh -> no defaults: absent deny targets are
    // placeholder-materialized on Windows, and planting a .ssh
    // skeleton into profiles that never used ssh is out of scope.
    rmSync(sshDir, { recursive: true, force: true })
    expect(collectSshKeyDenyPaths(rawHome)).toEqual([])
  })

  it('denies referenced paths that do not exist yet', () => {
    writeFileSync(
      join(sshDir, 'config'),
      `IdentityFile ${join(rawHome, 'no_such_key')}\n`,
    )
    expect(collectSshKeyDenyPaths(rawHome)).toContain(
      join(rawHome, 'no_such_key'),
    )
  })

  it('tolerates malformed lines without dropping valid ones', () => {
    writeFileSync(join(rawHome, 'good_key'), 'k')
    writeFileSync(
      join(sshDir, 'config'),
      [
        'this is not a directive at all !!!',
        'IdentityFile', // missing argument
        'Include', // missing argument
        '   # indented comment',
        '"unterminated quote',
        `IdentityFile "${join(rawHome, 'good_key')}"`,
        '',
      ].join('\n'),
    )

    const result = collectSshKeyDenyPaths(rawHome)
    expect(result).toContain(join(home, 'good_key'))
  })

  it('terminates on Include cycles', () => {
    writeFileSync(join(rawHome, 'cycle_key'), 'k')
    writeFileSync(
      join(sshDir, 'config'),
      `Include loop\nIdentityFile ${join(rawHome, 'cycle_key')}\n`,
    )
    writeFileSync(join(sshDir, 'loop'), 'Include config\n')

    const result = collectSshKeyDenyPaths(rawHome)
    expect(result).toContain(join(home, 'cycle_key'))
  })

  it('bounds Include recursion depth', () => {
    // Chain of 20 includes; the key at the end sits past the depth bound and
    // must be silently dropped rather than looping or throwing.
    writeFileSync(join(rawHome, 'deep_key'), 'k')
    writeFileSync(join(sshDir, 'config'), 'Include chain0\n')
    for (let i = 0; i < 19; i++) {
      writeFileSync(join(sshDir, `chain${i}`), `Include chain${i + 1}\n`)
    }
    writeFileSync(
      join(sshDir, 'chain19'),
      `IdentityFile ${join(rawHome, 'deep_key')}\n`,
    )

    const result = collectSshKeyDenyPaths(rawHome)
    expect(result).not.toContain(join(home, 'deep_key'))
  })

  it('collects IdentityAgent sockets (credential-equivalent)', () => {
    const agentSock = join(rawHome, 'agent.sock')
    writeFileSync(agentSock, '')
    writeFileSync(join(sshDir, 'config'), `IdentityAgent ${agentSock}\n`)
    expect(collectSshKeyDenyPaths(rawHome)).toContain(join(home, 'agent.sock'))
  })

  it('skips candidates containing glob metacharacters (would mis-deny)', () => {
    const weird = join(rawHome, 'keys[1]')
    writeFileSync(join(sshDir, 'config'), `IdentityFile ${weird}\n`)
    const result = collectSshKeyDenyPaths(rawHome)
    expect(result.some(p => p.includes('keys[1]'))).toBe(false)
  })

  it('skips IdentityFile none', () => {
    writeFileSync(join(sshDir, 'config'), 'IdentityFile none\n')
    const result = collectSshKeyDenyPaths(rawHome)
    expect(result.some(p => p.endsWith('none'))).toBe(false)
  })
})

describe('splitSshConfigLine', () => {
  it('splits keyword and argument on whitespace', () => {
    expect(splitSshConfigLine('IdentityFile ~/.ssh/id_rsa')).toEqual([
      'IdentityFile',
      '~/.ssh/id_rsa',
    ])
  })

  it('supports the keyword=argument form', () => {
    expect(splitSshConfigLine('IdentityFile=~/.ssh/id_rsa')).toEqual([
      'IdentityFile',
      '~/.ssh/id_rsa',
    ])
  })

  it('keeps = literal inside arguments', () => {
    expect(splitSshConfigLine('IdentityFile ~/a=b')).toEqual([
      'IdentityFile',
      '~/a=b',
    ])
  })

  it('handles double-quoted arguments containing spaces', () => {
    expect(splitSshConfigLine('IdentityFile "/my keys/id_rsa"')).toEqual([
      'IdentityFile',
      '/my keys/id_rsa',
    ])
  })

  it('splits multiple Include patterns', () => {
    expect(splitSshConfigLine('Include a b')).toEqual(['Include', 'a', 'b'])
  })
})

describe('expandSshPathTokens', () => {
  it('expands %% to a literal percent', () => {
    expect(expandSshPathTokens('/a/%%b', '/home/u')).toBe('/a/%b')
  })

  it('expands %d to the home directory', () => {
    expect(expandSshPathTokens('%d/key', '/home/u')).toBe('/home/u/key')
  })

  it('returns undefined for connection-scoped tokens', () => {
    expect(expandSshPathTokens('/a/%h', '/home/u')).toBeUndefined()
    expect(expandSshPathTokens('/a/%r', '/home/u')).toBeUndefined()
  })

  it('returns undefined for ${ENV} references and ~otheruser', () => {
    expect(expandSshPathTokens('${HOME}/key', '/home/u')).toBeUndefined()
    expect(expandSshPathTokens('~other/key', '/home/u')).toBeUndefined()
  })
})
