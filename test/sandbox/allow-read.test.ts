import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'
import { createMitmCA, disposeMitmCA } from '../../src/sandbox/mitm-ca.js'
import type {
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
} from '../../src/sandbox/sandbox-schemas.js'
import { isLinux, isMacOS, isSupportedPlatform } from '../helpers/platform.js'

/**
 * Tests for the allowRead (allowWithinDeny) feature.
 *
 * allowRead re-allows read access within regions blocked by denyRead.
 * allowRead takes precedence over denyRead — the opposite of write,
 * where denyWrite takes precedence over allowWrite.
 */
describe('allowRead precedence over denyRead', () => {
  const TEST_BASE_DIR = join(tmpdir(), 'allow-read-test-' + Date.now())
  const TEST_DENIED_DIR = join(TEST_BASE_DIR, 'denied')
  const TEST_ALLOWED_SUBDIR = join(TEST_DENIED_DIR, 'allowed')
  const TEST_SECRET_FILE = join(TEST_DENIED_DIR, 'secret.txt')
  const TEST_ALLOWED_FILE = join(TEST_ALLOWED_SUBDIR, 'visible.txt')
  const TEST_SECRET_CONTENT = 'TOP_SECRET'
  const TEST_ALLOWED_CONTENT = 'VISIBLE_DATA'

  beforeAll(() => {
    if (!isSupportedPlatform) return

    mkdirSync(TEST_ALLOWED_SUBDIR, { recursive: true })
    writeFileSync(TEST_SECRET_FILE, TEST_SECRET_CONTENT)
    writeFileSync(TEST_ALLOWED_FILE, TEST_ALLOWED_CONTENT)
  })

  afterAll(() => {
    if (existsSync(TEST_BASE_DIR)) {
      rmSync(TEST_BASE_DIR, { recursive: true, force: true })
    }
  })

  describe('macOS Seatbelt', () => {
    it.if(isMacOS)('should deny reading a file in a denied directory', () => {
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [TEST_DENIED_DIR],
        allowWithinDeny: [],
      }

      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `cat ${TEST_SECRET_FILE}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).not.toBe(0)
      expect(result.stdout).not.toContain(TEST_SECRET_CONTENT)
    })

    it.if(isMacOS)(
      'should allow reading a file in an allowWithinDeny subdirectory',
      () => {
        const readConfig: FsReadRestrictionConfig = {
          denyOnly: [TEST_DENIED_DIR],
          allowWithinDeny: [TEST_ALLOWED_SUBDIR],
        }

        const wrappedCommand = wrapCommandWithSandboxMacOS({
          command: `cat ${TEST_ALLOWED_FILE}`,
          needsNetworkRestriction: false,
          readConfig,
          writeConfig: undefined,
        })

        const result = spawnSync(wrappedCommand, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).toBe(0)
        expect(result.stdout).toContain(TEST_ALLOWED_CONTENT)
      },
    )

    it.if(isMacOS)(
      'should still deny reading files outside the re-allowed subdirectory',
      () => {
        const readConfig: FsReadRestrictionConfig = {
          denyOnly: [TEST_DENIED_DIR],
          allowWithinDeny: [TEST_ALLOWED_SUBDIR],
        }

        const wrappedCommand = wrapCommandWithSandboxMacOS({
          command: `cat ${TEST_SECRET_FILE}`,
          needsNetworkRestriction: false,
          readConfig,
          writeConfig: undefined,
        })

        const result = spawnSync(wrappedCommand, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).not.toBe(0)
        expect(result.stdout).not.toContain(TEST_SECRET_CONTENT)
      },
    )
  })

  describe('Linux bwrap', () => {
    it.if(isLinux)(
      'should deny reading a file in a denied directory',
      async () => {
        const readConfig: FsReadRestrictionConfig = {
          denyOnly: [TEST_DENIED_DIR],
          allowWithinDeny: [],
        }

        const wrappedCommand = await wrapCommandWithSandboxLinux({
          command: `cat ${TEST_SECRET_FILE}`,
          needsNetworkRestriction: false,
          readConfig,
          writeConfig: undefined,
        })

        const result = spawnSync(wrappedCommand, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).not.toBe(0)
        expect(result.stdout).not.toContain(TEST_SECRET_CONTENT)
      },
    )

    it.if(isLinux)(
      'should allow reading a file in an allowWithinDeny subdirectory',
      async () => {
        const readConfig: FsReadRestrictionConfig = {
          denyOnly: [TEST_DENIED_DIR],
          allowWithinDeny: [TEST_ALLOWED_SUBDIR],
        }

        const wrappedCommand = await wrapCommandWithSandboxLinux({
          command: `cat ${TEST_ALLOWED_FILE}`,
          needsNetworkRestriction: false,
          readConfig,
          writeConfig: undefined,
        })

        const result = spawnSync(wrappedCommand, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).toBe(0)
        expect(result.stdout).toContain(TEST_ALLOWED_CONTENT)
      },
    )

    it.if(isLinux)(
      'should still deny reading files outside the re-allowed subdirectory',
      async () => {
        const readConfig: FsReadRestrictionConfig = {
          denyOnly: [TEST_DENIED_DIR],
          allowWithinDeny: [TEST_ALLOWED_SUBDIR],
        }

        const wrappedCommand = await wrapCommandWithSandboxLinux({
          command: `cat ${TEST_SECRET_FILE}`,
          needsNetworkRestriction: false,
          readConfig,
          writeConfig: undefined,
        })

        const result = spawnSync(wrappedCommand, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).not.toBe(0)
        expect(result.stdout).not.toContain(TEST_SECRET_CONTENT)
      },
    )

    // Regression: the write-path skip check in the allowRead re-bind loop was
    // too broad — it skipped any allowPath under ANY allowWrite, not just
    // writes actually re-bound under this tmpfs. With allowWrite as an
    // ancestor of denyRead (not wiped, not re-bound), allowRead under it was
    // skipped and left sitting in the empty tmpfs.
    // Shape: allowWrite: [~], denyRead: [~/.ssh], allowRead: [~/.ssh/known_hosts].
    it.if(isLinux)(
      'should re-allow under denyRead when allowWrite is an ancestor of the deny',
      async () => {
        const wrappedCommand = await wrapCommandWithSandboxLinux({
          command: `cat ${TEST_ALLOWED_FILE}`,
          needsNetworkRestriction: false,
          readConfig: {
            denyOnly: [TEST_DENIED_DIR],
            allowWithinDeny: [TEST_ALLOWED_SUBDIR],
          },
          writeConfig: {
            allowOnly: [TEST_BASE_DIR], // ancestor of denyRead
            denyWithinAllow: [],
          },
        })

        const result = spawnSync(wrappedCommand, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).toBe(0)
        expect(result.stdout).toContain(TEST_ALLOWED_CONTENT)
      },
    )
  })
})

/**
 * Regression: denyRead: ['/'] + allowRead: [<project>] used to deny everything.
 *
 * macOS: (subpath "/") denies the root inode; no allowWithinDeny subpath covers
 *   "/", so dyld SIGABRTs before exec. Fix emits (allow file-read* (literal "/")).
 * Linux: --tmpfs / wiped all prior mounts, and the carve-out prefix check
 *   startsWith('/' + '/') never matched. Fix expands '/' into its children.
 *
 * Test dir lives under $HOME (not tmpdir) so the macOS /tmp → /private/tmp
 * symlink doesn't confuse Seatbelt path matching.
 */
describe('allowRead carve-out with denyRead at filesystem root (issue #10)', () => {
  const TEST_DIR = join(
    homedir(),
    '.sandbox-runtime-test-root-deny-' + Date.now(),
  )
  const TEST_FILE = join(TEST_DIR, 'visible.txt')
  const TEST_CONTENT = 'ROOT_CARVE_OUT'
  // Paths needed for sh/cat to load at all when the whole filesystem is denied.
  // /private covers /tmp and /var (macOS symlinks). /lib* for Linux ld.so.
  const EXEC_DEPS = [
    '/bin',
    '/usr',
    '/lib',
    '/lib64',
    '/System',
    '/private',
    '/dev',
    '/etc',
  ]

  beforeAll(() => {
    if (!isSupportedPlatform) return
    mkdirSync(TEST_DIR, { recursive: true })
    writeFileSync(TEST_FILE, TEST_CONTENT)
  })

  afterAll(() => {
    if (existsSync(TEST_DIR)) {
      rmSync(TEST_DIR, { recursive: true, force: true })
    }
  })

  it.if(isMacOS)('macOS: re-allows carve-out under a root-level deny', () => {
    const readConfig: FsReadRestrictionConfig = {
      denyOnly: ['/'],
      allowWithinDeny: [TEST_DIR, ...EXEC_DEPS],
    }

    // EXEC_DEPS covers /bin and /usr but not /opt/homebrew — pin the shell
    // so denying the filesystem root doesn't break execvp on Homebrew-bash Macs.
    const wrappedCommand = wrapCommandWithSandboxMacOS({
      command: `cat ${TEST_FILE}`,
      needsNetworkRestriction: false,
      readConfig,
      writeConfig: undefined,
      binShell: '/bin/bash',
    })

    const result = spawnSync(wrappedCommand, {
      shell: true,
      encoding: 'utf8',
      timeout: 5000,
    })

    expect(result.status).toBe(0)
    expect(result.stdout).toContain(TEST_CONTENT)
  })

  it.if(isMacOS)(
    'macOS: still denies paths outside the carve-out under a root-level deny',
    () => {
      const outside = join(homedir(), '.bashrc')
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: ['/'],
        allowWithinDeny: [TEST_DIR, ...EXEC_DEPS],
      }

      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `cat ${outside} 2>/dev/null; true`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
        binShell: '/bin/bash',
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // Process must exec (no SIGABRT) and stdout must be empty (cat denied)
      expect(result.status).toBe(0)
      expect(result.stdout).toBe('')
    },
  )

  it.if(isLinux)(
    'Linux: re-allows carve-out under a root-level deny',
    async () => {
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: ['/'],
        allowWithinDeny: [TEST_DIR, ...EXEC_DEPS],
      }

      // allowAllUnixSockets: true bypasses the seccomp path — otherwise the
      // apply-seccomp binary under <repo>/vendor/ is hidden by the root deny.
      const wrappedCommand = await wrapCommandWithSandboxLinux({
        command: `cat ${TEST_FILE}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
        allowAllUnixSockets: true,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).toBe(0)
      expect(result.stdout).toContain(TEST_CONTENT)
    },
  )

  it.if(isLinux)(
    'Linux: still denies paths outside the carve-out under a root-level deny',
    async () => {
      const outside = join(homedir(), '.bashrc')
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: ['/'],
        allowWithinDeny: [TEST_DIR, ...EXEC_DEPS],
      }

      const wrappedCommand = await wrapCommandWithSandboxLinux({
        command: `cat ${outside} 2>/dev/null; true`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
        allowAllUnixSockets: true,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).toBe(0)
      expect(result.stdout).toBe('')
    },
  )

  it.if(isLinux)(
    'Linux: preserves write binds when denyRead ancestor wipes them',
    async () => {
      const writeTarget = join(TEST_DIR, 'written.txt')
      const wrappedCommand = await wrapCommandWithSandboxLinux({
        command: `echo WRITE_OK > ${writeTarget} && cat ${writeTarget}`,
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: ['/'],
          allowWithinDeny: [...EXEC_DEPS],
        },
        writeConfig: {
          allowOnly: [TEST_DIR],
          denyWithinAllow: [],
        },
        allowAllUnixSockets: true,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).toBe(0)
      expect(result.stdout).toContain('WRITE_OK')
    },
  )
})

/**
 * Tests that allowRead-only configs (no denyRead) do not trigger sandbox overhead.
 */
describe('allowRead without denyRead does not trigger sandboxing', () => {
  const command = 'echo hello'

  it.if(isMacOS)(
    'returns command unchanged on macOS when only allowWithinDeny is set',
    () => {
      const result = wrapCommandWithSandboxMacOS({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [], allowWithinDeny: ['/some/path'] },
        writeConfig: undefined,
      })

      expect(result).toBe(command)
    },
  )

  it.if(isLinux)(
    'returns command unchanged on Linux when only allowWithinDeny is set',
    async () => {
      const result = await wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [], allowWithinDeny: ['/some/path'] },
        writeConfig: undefined,
      })

      expect(result).toBe(command)
    },
  )
})

// A literal denyRead path nested under a literal allowRead subpath must keep
// its deny: Seatbelt is last-match-wins, so the deny is re-emitted after the
// allow. (Glob denies are re-emitted too — see macos-glob-deny-reemit.test.ts
// for the profile text and 'macOS glob denyRead inside allowRead' below for
// enforcement.)
describe.if(isMacOS)('macOS denyRead nested under allowRead', () => {
  it('re-emits the deny after the allow so it stays denied', () => {
    const result = wrapCommandWithSandboxMacOS({
      command: 'cat /work/secrets/key',
      needsNetworkRestriction: false,
      readConfig: {
        denyOnly: ['/work/secrets'],
        allowWithinDeny: ['/work'],
      },
      writeConfig: undefined,
    })
    // The profile is embedded in a shell command, so quotes are escaped —
    // match on the unquoted skeleton.
    const allowAt = result.indexOf('(allow file-read*\n  (subpath')
    const lastDenySecrets = result.lastIndexOf('/work/secrets')
    const firstDenySecrets = result.indexOf('/work/secrets')
    expect(allowAt).toBeGreaterThan(-1)
    // The deny on /work/secrets appears both before and after the allow:
    // original emit, then re-emit after allowWithinDeny.
    expect(firstDenySecrets).toBeLessThan(allowAt)
    expect(lastDenySecrets).toBeGreaterThan(allowAt)
  })
})

describe('rm in allowWrite under denyRead ancestor (issue #171)', () => {
  const TEST_BASE_DIR = join(tmpdir(), 'rm-under-denyread-' + Date.now())
  const TEST_PROJECT_DIR = join(TEST_BASE_DIR, 'project')
  const TEST_OUTSIDE_DIR = join(TEST_BASE_DIR, 'outside')

  beforeAll(() => {
    if (!isSupportedPlatform) return

    mkdirSync(TEST_PROJECT_DIR, { recursive: true })
    mkdirSync(TEST_OUTSIDE_DIR, { recursive: true })
  })

  afterAll(() => {
    if (existsSync(TEST_BASE_DIR)) {
      rmSync(TEST_BASE_DIR, { recursive: true, force: true })
    }
  })

  describe('macOS Seatbelt', () => {
    // The read section's move-blocking rules emit a broad
    // (deny file-write-unlink (subpath <denyRead>)) that a specific
    // (allow file-write*) does not override. Without a re-allow for
    // file-write-unlink on allowWrite paths, rm fails even though
    // touch/write succeed.

    it.if(isMacOS)(
      'should allow rm inside an allowWrite path under a denyRead ancestor',
      () => {
        const targetFile = join(TEST_PROJECT_DIR, 'deleteme.txt')
        writeFileSync(targetFile, 'data')

        const readConfig: FsReadRestrictionConfig = {
          denyOnly: [TEST_BASE_DIR],
          allowWithinDeny: [TEST_PROJECT_DIR],
        }
        const writeConfig: FsWriteRestrictionConfig = {
          allowOnly: [TEST_PROJECT_DIR],
          denyWithinAllow: [],
        }

        const wrappedCommand = wrapCommandWithSandboxMacOS({
          command: `rm ${targetFile}`,
          needsNetworkRestriction: false,
          readConfig,
          writeConfig,
        })

        const result = spawnSync(wrappedCommand, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).toBe(0)
        expect(existsSync(targetFile)).toBe(false)
      },
    )

    it.if(isMacOS)(
      'should still block rm outside allowWrite under the same denyRead ancestor',
      () => {
        const protectedFile = join(TEST_OUTSIDE_DIR, 'protected.txt')
        writeFileSync(protectedFile, 'data')

        const readConfig: FsReadRestrictionConfig = {
          denyOnly: [TEST_BASE_DIR],
          allowWithinDeny: [TEST_PROJECT_DIR],
        }
        const writeConfig: FsWriteRestrictionConfig = {
          allowOnly: [TEST_PROJECT_DIR],
          denyWithinAllow: [],
        }

        const wrappedCommand = wrapCommandWithSandboxMacOS({
          command: `rm ${protectedFile}`,
          needsNetworkRestriction: false,
          readConfig,
          writeConfig,
        })

        const result = spawnSync(wrappedCommand, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).not.toBe(0)
        expect(existsSync(protectedFile)).toBe(true)
      },
    )

    it.if(isMacOS)(
      'should still block rm of denyWithinAllow paths despite the re-allow',
      () => {
        // The re-allow of file-write-unlink for allowWrite paths is emitted in
        // the read section. The write section's own move-blocking rules for
        // denyWithinAllow are emitted later and must win (last-match).
        const protectedDir = join(TEST_PROJECT_DIR, 'protected')
        const protectedFile = join(protectedDir, 'keep.txt')
        mkdirSync(protectedDir, { recursive: true })
        writeFileSync(protectedFile, 'data')

        const readConfig: FsReadRestrictionConfig = {
          denyOnly: [TEST_BASE_DIR],
          allowWithinDeny: [TEST_PROJECT_DIR],
        }
        const writeConfig: FsWriteRestrictionConfig = {
          allowOnly: [TEST_PROJECT_DIR],
          denyWithinAllow: [protectedDir],
        }

        const wrappedCommand = wrapCommandWithSandboxMacOS({
          command: `rm ${protectedFile}`,
          needsNetworkRestriction: false,
          readConfig,
          writeConfig,
        })

        const result = spawnSync(wrappedCommand, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).not.toBe(0)
        expect(existsSync(protectedFile)).toBe(true)
      },
    )
  })

  describe('Linux bwrap', () => {
    // #190 fixed the Linux analogue by re-binding allowWrite paths after
    // the denyRead tmpfs wipes them. Verify rm works end-to-end.

    it.if(isLinux)(
      'should allow rm inside an allowWrite path under a denyRead ancestor',
      async () => {
        const targetFile = join(TEST_PROJECT_DIR, 'deleteme-linux.txt')
        writeFileSync(targetFile, 'data')

        const readConfig: FsReadRestrictionConfig = {
          denyOnly: [TEST_BASE_DIR],
          allowWithinDeny: [TEST_PROJECT_DIR],
        }
        const writeConfig: FsWriteRestrictionConfig = {
          allowOnly: [TEST_PROJECT_DIR],
          denyWithinAllow: [],
        }

        const wrappedCommand = await wrapCommandWithSandboxLinux({
          command: `rm ${targetFile}`,
          needsNetworkRestriction: false,
          readConfig,
          writeConfig,
        })

        const result = spawnSync(wrappedCommand, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).toBe(0)
        expect(existsSync(targetFile)).toBe(false)
      },
    )
  })
})

/**
 * Glob denyRead entries inside an allowRead region (the common shape is
 * denyRead: ["**\/.env"], allowRead: ["."]).
 *
 * Seatbelt is last-match-wins. The profile used to emit the glob denies,
 * then the allowRead allows, and re-emit only LITERAL denies afterwards —
 * so every glob deny landing inside an allowRead directory was silently
 * re-allowed. It now re-emits glob denies too (minus the allow entries the
 * glob itself covers), renders glob denies to cover the matched subtree,
 * and re-denies unlink of read-denied paths inside write roots so `mv`
 * can't carry them to a name the deny doesn't match. All of these run the
 * real profile under sandbox-exec.
 *
 * Config paths are built from the raw tmpdir() spelling (/var/folders/… on
 * macOS) while the commands use the realpath'd one (/private/var/…): the
 * glob's static prefix has to survive normalizePathForSandbox's realpath
 * for any of this to match.
 */
describe.if(isMacOS)('macOS glob denyRead inside allowRead (deny wins)', () => {
  const NAME = 'glob-deny-reemit-' + Date.now()
  const RAW_BASE = join(tmpdir(), NAME)
  const RAW_PROJECT = join(RAW_BASE, 'project')
  let BASE = ''
  let PROJECT = ''

  const SECRET = 'GLOB_DENY_SECRET_' + Date.now()
  const PLAIN = 'PLAIN_CONTENT_OK'

  /**
   * Whether the volume holding the tree folds case in file names. Decided
   * while the block is collected, so the `.ENV` spelling below is skipped
   * where it cannot resolve rather than passing for the wrong reason.
   */
  const volumeFoldsCase = ((): boolean => {
    const probeDir = join(tmpdir(), 'case-fold-probe-' + Date.now())
    try {
      mkdirSync(probeDir, { recursive: true })
      writeFileSync(join(probeDir, 'probe'), 'x')
      return existsSync(join(probeDir, 'PROBE'))
    } finally {
      rmSync(probeDir, { recursive: true, force: true })
    }
  })()

  /** Second spelling of the data volume; absent before macOS 10.15. */
  const DATA_FIRMLINK = '/System/Volumes/Data'

  type Tree = Record<string, string>
  const TREE: Tree = {
    '.env': SECRET,
    'sub/.env': SECRET,
    'secrets/key': SECRET,
    'secrets/deep/nested.txt': SECRET,
    'certs/a.key': SECRET,
    'conf/ok.pem': PLAIN,
    'conf/bad.pem': SECRET,
    'plain.txt': PLAIN,
    'deleteme.txt': 'x',
    'other/.keep': 'x',
  }

  function resetTree(): void {
    rmSync(RAW_BASE, { recursive: true, force: true })
    mkdirSync(RAW_PROJECT, { recursive: true })
    BASE = realpathSync(RAW_BASE)
    PROJECT = join(BASE, 'project')
    for (const [rel, content] of Object.entries(TREE)) {
      const abs = join(PROJECT, rel)
      mkdirSync(join(abs, '..'), { recursive: true })
      writeFileSync(abs, content)
    }
    writeFileSync(join(BASE, 'outside.txt'), SECRET)
  }

  beforeAll(resetTree)
  afterAll(() => {
    rmSync(RAW_BASE, { recursive: true, force: true })
  })

  const PROJECT_READ = (): FsReadRestrictionConfig => ({
    denyOnly: [
      join(RAW_PROJECT, '**', '.env'),
      // What `<project>/**/secrets/**` becomes after sandbox-manager strips
      // the trailing `/**`.
      join(RAW_PROJECT, '**', 'secrets'),
      // Root-anchored, as a credentials.files-style deny would be.
      '/**/*.key',
    ],
    allowWithinDeny: [RAW_PROJECT],
  })
  const PROJECT_WRITE = (): FsWriteRestrictionConfig => ({
    allowOnly: [RAW_PROJECT],
    denyWithinAllow: [],
  })

  function run(
    command: string,
    readConfig: FsReadRestrictionConfig,
    writeConfig?: FsWriteRestrictionConfig,
  ): { status: number | null; stdout: string; stderr: string } {
    const wrapped = wrapCommandWithSandboxMacOS({
      command,
      needsNetworkRestriction: false,
      readConfig,
      writeConfig,
    })
    const r = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })
    expect(r.error).toBeUndefined()
    return { status: r.status, stdout: r.stdout, stderr: r.stderr }
  }

  describe('reads are denied', () => {
    it.each([
      ['.env at the project root', '.env'],
      ['.env in a subdirectory', 'sub/.env'],
      ['a file directly inside a **/secrets match', 'secrets/key'],
      ['a file deeper inside a **/secrets match', 'secrets/deep/nested.txt'],
      [
        'a root-anchored /**/*.key match inside the allowRead dir',
        'certs/a.key',
      ],
    ])('cat: %s', (_label, rel) => {
      const r = run(`cat ${join(PROJECT, rel)}`, PROJECT_READ())
      expect(r.status).not.toBe(0)
      expect(r.stdout).not.toContain(SECRET)
    })

    it('stat is denied too (file-read-metadata is only re-allowed for directories)', () => {
      const r = run(`stat ${join(PROJECT, '.env')}`, PROJECT_READ())
      expect(r.status).not.toBe(0)
    })

    it('a non-matching file in the same allowRead dir is still readable', () => {
      const r = run(`cat ${join(PROJECT, 'plain.txt')}`, PROJECT_READ())
      expect(r.status).toBe(0)
      expect(r.stdout).toContain(PLAIN)
    })

    it('a credentials-style *.pem glob denies siblings of an allowed file', () => {
      // credentials.files {mode: 'deny'} entries are unioned into denyOnly
      // upstream, so this is the same shape they take by the time the
      // profile is built. ok.pem is a specific file allow the glob covers,
      // so it is carved out of the re-emitted deny; bad.pem is not.
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [join(RAW_PROJECT, 'conf', '*.pem')],
        allowWithinDeny: [RAW_PROJECT, join(RAW_PROJECT, 'conf', 'ok.pem')],
      }
      const ok = run(`cat ${join(PROJECT, 'conf/ok.pem')}`, readConfig)
      expect(ok.status).toBe(0)
      expect(ok.stdout).toContain(PLAIN)
      const bad = run(`cat ${join(PROJECT, 'conf/bad.pem')}`, readConfig)
      expect(bad.status).not.toBe(0)
      expect(bad.stdout).not.toContain(SECRET)
    })

    it('keeps the tlsTerminate trust bundle readable under a /**/*.crt deny', async () => {
      // sandbox-manager pushes certPath + trustBundlePath into
      // allowWithinDeny. The bundle is a specific file the glob covers, so
      // the re-emitted deny carves it out — without an allow after the
      // denies. A .crt the user did NOT allow stays denied.
      const ca = createMitmCA({})
      const userCrt = join(PROJECT, 'conf', 'user.crt')
      writeFileSync(userCrt, SECRET)
      try {
        const readConfig: FsReadRestrictionConfig = {
          denyOnly: ['/**/*.crt'],
          allowWithinDeny: [RAW_PROJECT, ca.certPath, ca.trustBundlePath],
        }
        const bundle = run(`head -c 27 ${ca.trustBundlePath}`, readConfig)
        expect(bundle.status).toBe(0)
        expect(bundle.stdout).toBe('-----BEGIN CERTIFICATE-----')
        const denied = run(`cat ${userCrt}`, readConfig)
        expect(denied.status).not.toBe(0)
        expect(denied.stdout).not.toContain(SECRET)
      } finally {
        await disposeMitmCA(ca)
      }
    })
  })

  describe('rename cannot carry a denied path to an unmatched name', () => {
    beforeAll(resetTree)

    it.each([
      ['glob-matched file (**/.env)', '.env', 'moved.txt', 'moved.txt'],
      ['glob-matched dir (**/secrets)', 'secrets', 's2', 's2/key'],
    ])(
      '%s: mv fails and the target stays unreadable',
      (_l, src, dst, probe) => {
        const r = run(
          `mv ${join(PROJECT, src)} ${join(PROJECT, dst)}; cat ${join(PROJECT, probe)}; true`,
          PROJECT_READ(),
          PROJECT_WRITE(),
        )
        expect(r.stdout).not.toContain(SECRET)
        expect(existsSync(join(PROJECT, src))).toBe(true)
        expect(existsSync(join(PROJECT, dst))).toBe(false)
      },
    )

    it('literal deny nested under allowRead: mv of the dir fails', () => {
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [join(RAW_PROJECT, 'secrets')],
        allowWithinDeny: [RAW_PROJECT],
      }
      const r = run(
        `mv ${join(PROJECT, 'secrets')} ${join(PROJECT, 's3')}; cat ${join(PROJECT, 's3/key')}; true`,
        readConfig,
        PROJECT_WRITE(),
      )
      expect(r.stdout).not.toContain(SECRET)
      expect(existsSync(join(PROJECT, 'secrets'))).toBe(true)
    })

    it('literal deny with no allowRead at all: mv of the dir still fails', () => {
      // The pre-existing bypass did not need allowRead: the write root's
      // unlink re-allow alone re-opened any deny sitting inside it.
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [join(RAW_PROJECT, 'secrets')],
        allowWithinDeny: [],
      }
      const r = run(
        `mv ${join(PROJECT, 'secrets')} ${join(PROJECT, 's4')}; cat ${join(PROJECT, 's4/key')}; true`,
        readConfig,
        PROJECT_WRITE(),
      )
      expect(r.stdout).not.toContain(SECRET)
      expect(existsSync(join(PROJECT, 'secrets'))).toBe(true)
    })

    it('the enclosing directory of a deeper deny cannot be renamed either', () => {
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [join(RAW_PROJECT, 'secrets', 'deep', 'nested.txt')],
        allowWithinDeny: [RAW_PROJECT],
      }
      const r = run(
        `mv ${join(PROJECT, 'secrets')} ${join(PROJECT, 's5')}; cat ${join(PROJECT, 's5/deep/nested.txt')}; true`,
        readConfig,
        PROJECT_WRITE(),
      )
      expect(r.stdout).not.toContain(SECRET)
      expect(existsSync(join(PROJECT, 'secrets/deep/nested.txt'))).toBe(true)
    })
  })

  describe('everything else inside the write root still works', () => {
    beforeAll(resetTree)

    it('rm of a non-denied file', () => {
      const target = join(PROJECT, 'deleteme.txt')
      const r = run(`rm ${target}`, PROJECT_READ(), PROJECT_WRITE())
      expect(r.status).toBe(0)
      expect(existsSync(target)).toBe(false)
    })

    it('creating a new file at a read-denied name (unlink is re-denied, create is not)', () => {
      const target = join(PROJECT, 'other', '.env')
      const r = run(`echo fresh > ${target}`, PROJECT_READ(), PROJECT_WRITE())
      expect(r.status).toBe(0)
      expect(readFileSync(target, 'utf8')).toBe('fresh\n')
    })

    it('rm inside an allowRead carve-out nested in a literal deny', () => {
      // denyRead <project>/secrets, allowRead <project>/secrets/deep,
      // allowWrite <project>: the trailing unlink re-deny on secrets must
      // subtract deep, or rm there regresses the way #171 did. (The project
      // dir itself is deliberately not in allowRead: a literal deny nested
      // under a literal allow is re-emitted after ALL allows — pre-existing
      // behavior — which would make deep unreadable and rm's lstat fail
      // before unlink is ever attempted.)
      const target = join(PROJECT, 'secrets', 'deep', 'nested.txt')
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [join(RAW_PROJECT, 'secrets')],
        allowWithinDeny: [join(RAW_PROJECT, 'secrets', 'deep')],
      }
      const r = run(`rm ${target}`, readConfig, PROJECT_WRITE())
      expect(r.status).toBe(0)
      expect(existsSync(target)).toBe(false)
    })
  })

  describe('region-shaped globs keep working', () => {
    beforeAll(resetTree)

    // These two are also the mechanism check for the re-emitted deny's
    // shape: (require-all (regex …) (require-not (subpath …))) and
    // (require-all (regex …) (require-not (regex …))) both have to compile
    // under sandbox-exec AND leave exactly the carved entry readable.
    it('<base>/**/* deny + literal allowRead carve-out: carve-out readable, rest denied', () => {
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [join(RAW_BASE, '**', '*')],
        allowWithinDeny: [RAW_PROJECT],
      }
      const inside = run(`cat ${join(PROJECT, 'plain.txt')}`, readConfig)
      expect(inside.status).toBe(0)
      expect(inside.stdout).toContain(PLAIN)
      const outside = run(`cat ${join(BASE, 'outside.txt')}`, readConfig)
      expect(outside.status).not.toBe(0)
      expect(outside.stdout).not.toContain(SECRET)
    })

    it('<base>/**/* deny + glob allowRead carve-out: matching file readable, rest denied', () => {
      // A glob allow matches paths exactly (no subtree), so it has to name
      // the file itself; the region deny is carved by that allow's regex.
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [join(RAW_BASE, '**', '*')],
        allowWithinDeny: [join(RAW_PROJECT, '*.txt')],
      }
      const wrapped = wrapCommandWithSandboxMacOS({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })
      expect(wrapped).toContain('(require-not (regex ')
      const inside = run(`cat ${join(PROJECT, 'plain.txt')}`, readConfig)
      expect(inside.status).toBe(0)
      expect(inside.stdout).toContain(PLAIN)
      const sibling = run(`cat ${join(PROJECT, 'secrets', 'key')}`, readConfig)
      expect(sibling.status).not.toBe(0)
      expect(sibling.stdout).not.toContain(SECRET)
    })

    it('rm inside the carve-out of a region glob that also sits in a write root', () => {
      const target = join(PROJECT, 'deleteme.txt')
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [join(RAW_BASE, '**', '*')],
        allowWithinDeny: [RAW_PROJECT],
      }
      const r = run(`rm ${target}`, readConfig, PROJECT_WRITE())
      expect(r.status).toBe(0)
      expect(existsSync(target)).toBe(false)
    })
  })

  /**
   * Spellings that reach a denied file by another name. The deny is written
   * against one path; each case pins whether the alias gets past it, so a
   * build that starts leaking through one of them fails here.
   */
  describe('adjacent aliasing behaviors', () => {
    beforeAll(resetTree)

    it('hard link to a denied file (ln .env x; cat x)', () => {
      const link = join(PROJECT, 'hardlink.txt')
      const r = run(
        `ln ${join(PROJECT, '.env')} ${link} 2>&1 && echo LN_OK; cat ${link} 2>&1; true`,
        PROJECT_READ(),
        PROJECT_WRITE(),
      )
      expect(r.stdout).not.toContain('LN_OK')
      expect(existsSync(link)).toBe(false)
      expect(r.stdout).not.toContain(SECRET)
    })

    it('(deny file-link …) compiles and blocks ln', () => {
      // The hard link above is closed by the read deny on the source. This
      // pins that Seatbelt here also takes file-link, so a deny-only rule
      // could close it at the link itself the way unlink is closed.
      const link = join(PROJECT, 'hardlink2.txt')
      const profile =
        '(version 1) (allow default) ' +
        `(deny file-link (subpath ${JSON.stringify(PROJECT)}))`
      const r = spawnSync(
        '/usr/bin/sandbox-exec',
        [
          '-p',
          profile,
          '/bin/sh',
          '-c',
          `ln ${join(PROJECT, 'plain.txt')} ${link}`,
        ],
        { encoding: 'utf8', timeout: 10000 },
      )
      expect(r.status).not.toBe(0)
      // `ln` names itself in the denial. A profile Seatbelt refused to
      // parse or apply fails the same command without ever reaching it,
      // and says so under its own name instead.
      expect(r.stderr).toContain('ln:')
      expect(r.stderr).toContain('Operation not permitted')
      expect(existsSync(link)).toBe(false)
    })

    it('clonefile of a denied file (cp -c .env x; cat x)', () => {
      const clone = join(PROJECT, 'clone.txt')
      const r = run(
        `cp -c ${join(PROJECT, '.env')} ${clone} 2>&1 && echo CP_OK; cat ${clone} 2>&1; true`,
        PROJECT_READ(),
        PROJECT_WRITE(),
      )
      expect(r.stdout).not.toContain('CP_OK')
      expect(existsSync(clone)).toBe(false)
      expect(r.stdout).not.toContain(SECRET)
    })

    it.if(volumeFoldsCase)(
      'case-folded spelling on a case-insensitive volume (cat .ENV)',
      () => {
        const spelling = join(PROJECT, '.ENV')
        const probe = spawnSync('/bin/sh', ['-c', `cat ${spelling}`], {
          encoding: 'utf8',
        })
        // Unsandboxed, the spelling reaches the file: the deny is what
        // stops the sandboxed read below, not a missing path.
        expect(probe.stdout).toContain(SECRET)
        const r = run(`cat ${spelling} 2>&1; true`, PROJECT_READ())
        expect(r.stdout).not.toContain(SECRET)
      },
    )

    it.if(existsSync(DATA_FIRMLINK))(
      'firmlink spelling (/System/Volumes/Data<path>)',
      () => {
        const alias = join(DATA_FIRMLINK, join(PROJECT, '.env'))
        expect(existsSync(alias)).toBe(true)
        const r = run(`cat ${alias} 2>&1; true`, PROJECT_READ())
        expect(r.stdout).not.toContain(SECRET)
      },
    )
  })
})

/**
 * denyRead: ['/'] plus a `/*` glob. The re-emitted `/*` (rendered as a
 * subtree regex) matches "/" itself, so the root re-allow that keeps dyld
 * alive has to land after it — otherwise nothing execs. Same fixture shape
 * as the issue #10 test above.
 */
describe.if(isMacOS)('macOS root deny alongside a /* glob deny', () => {
  const TEST_DIR = join(
    homedir(),
    '.sandbox-runtime-test-root-glob-' + Date.now(),
  )
  const TEST_FILE = join(TEST_DIR, 'visible.txt')
  // Sibling of TEST_DIR: under $HOME, outside every carve-out.
  const OUTSIDE_FILE = TEST_DIR + '-outside.txt'
  const EXEC_DEPS = ['/bin', '/usr', '/System', '/private', '/dev', '/etc']

  beforeAll(() => {
    mkdirSync(TEST_DIR, { recursive: true })
    writeFileSync(TEST_FILE, 'ROOT_GLOB_VISIBLE')
    writeFileSync(OUTSIDE_FILE, 'ROOT_GLOB_OUTSIDE')
  })
  afterAll(() => {
    rmSync(TEST_DIR, { recursive: true, force: true })
    rmSync(OUTSIDE_FILE, { force: true })
  })

  it('still execs, reads the carve-out, and denies the rest', () => {
    const readConfig: FsReadRestrictionConfig = {
      denyOnly: ['/', '/*'],
      allowWithinDeny: [TEST_DIR, ...EXEC_DEPS],
    }
    const wrapped = wrapCommandWithSandboxMacOS({
      command: `echo ROOT_GLOB_EXEC_OK; cat ${TEST_FILE}; cat ${OUTSIDE_FILE} 2>/dev/null; true`,
      needsNetworkRestriction: false,
      readConfig,
      writeConfig: undefined,
      binShell: '/bin/bash',
    })
    const r = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })
    expect(r.status).toBe(0)
    expect(r.stdout).toContain('ROOT_GLOB_EXEC_OK')
    expect(r.stdout).toContain('ROOT_GLOB_VISIBLE')
    expect(r.stdout).not.toContain('ROOT_GLOB_OUTSIDE')
  })
})
