import { afterAll, describe, it, expect } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { isMacOS } from '../helpers/platform.js'

/**
 * Tests for the opt-in allowAppleEvents option (macOS only).
 *
 * By default the Seatbelt profile's (deny default) withholds appleevent-send
 * and the com.apple.coreservices.appleevents mach-lookup, and macOS enforces
 * both: `open` fails at Launch Services and a real event to a running app
 * (`tell application "Finder" to get name of startup disk`) fails with -600
 * ("Application isn't running"). On top of the deny the profile removes the
 * scripting runtime as defense in depth: exec of the stock scripting tools
 * and read of the OSA language components (which every AppleScript/JXA compile
 * needs, whichever API reaches them) are denied, and that is what these tests pin.
 */

function wrapCommand(command: string, allowAppleEvents?: boolean): string {
  return wrapCommandWithSandboxMacOS({
    command,
    needsNetworkRestriction: true,
    allowAppleEvents,
    readConfig: undefined,
    writeConfig: undefined,
  })
}

describe.if(isMacOS)(
  'macOS Seatbelt allowAppleEvents profile generation',
  () => {
    it('omits Apple Events rules by default', () => {
      const wrapped = wrapCommand('echo test')

      expect(wrapped).not.toContain('(allow appleevent-send)')
      expect(wrapped).not.toContain(
        '(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))',
      )
    })

    it('generates an identical command when unset and when explicitly false', () => {
      const unset = wrapCommand('echo test')
      const explicitFalse = wrapCommand('echo test', false)

      expect(explicitFalse).toBe(unset)
    })

    it('denies exec of the scripting tools by default', () => {
      const wrapped = wrapCommand('echo test')

      expect(wrapped).toContain('(deny process-exec')
      for (const toolPath of [
        '/usr/bin/osascript',
        '/usr/bin/osacompile',
        '/usr/bin/automator',
        '/usr/bin/shortcuts',
      ]) {
        expect(wrapped).toContain(`(literal "${toolPath}")`)
      }
    })

    it('leaves the scripting tools executable when enabled', () => {
      const wrapped = wrapCommand('echo test', true)

      expect(wrapped).not.toContain('(deny process-exec')
    })

    it('denies read of the OSA language components by default', () => {
      const wrapped = wrapCommand('echo test')

      for (const componentPath of [
        '/System/Library/Components/AppleScript.component',
        '/System/Library/Components/JavaScript.component',
      ]) {
        expect(wrapped).toContain(`(subpath "${componentPath}")`)
      }
    })

    it('emits the component deny after every file-read allow', () => {
      // Last match wins in Seatbelt, so a read allow landing after the deny
      // would re-open the components. Two allows could: an allowWithinDeny
      // covering the components, and the pty block's file-read*/file-write*
      // rule, which is emitted after the whole read section.
      const wrapped = wrapCommandWithSandboxMacOS({
        command: 'echo test',
        needsNetworkRestriction: true,
        readConfig: {
          denyOnly: ['/System'],
          allowWithinDeny: ['/System/Library'],
        },
        writeConfig: undefined,
        allowPty: true,
      })

      const componentDeny = wrapped.indexOf(
        '(subpath "/System/Library/Components/AppleScript.component")',
      )
      expect(componentDeny).toBeGreaterThan(-1)
      expect(wrapped.lastIndexOf('(allow file-read*')).toBeLessThan(
        componentDeny,
      )
    })

    it('leaves the OSA language components readable when enabled', () => {
      const wrapped = wrapCommand('echo test', true)

      expect(wrapped).not.toContain('AppleScript.component')
      expect(wrapped).not.toContain('JavaScript.component')
    })

    it('includes Apple Events rules when enabled', () => {
      const wrapped = wrapCommand('echo test', true)

      // The profile is embedded byte-literal inside a single-quoted argument;
      // matching rule fragments keeps the assertion focused on the rules.
      expect(wrapped).toContain('(allow appleevent-send)')
      expect(wrapped).toContain('com.apple.coreservices.appleevents')
    })

    it('produces a profile that sandbox-exec accepts when enabled', () => {
      const wrapped = wrapCommand('echo APPLE_EVENTS_OK', true)
      const result = spawnSync(wrapped, {
        shell: true,
        encoding: 'utf8',
        timeout: 10000,
      })

      expect(result.status).toBe(0)
      expect(result.stdout).toContain('APPLE_EVENTS_OK')
    })
  },
)

describe.if(isMacOS)('macOS Seatbelt osascript exec deny end to end', () => {
  const probe =
    'osascript -e \'tell application "Finder" to get name of startup disk\''

  // Unlike the `open` probes below this needs no TCC automation grant: the
  // command dies at exec, before any Apple Event is sent, so it is safe to
  // assert everywhere.
  it('blocks osascript by default', () => {
    const result = spawnSync(wrapCommand(probe), {
      shell: true,
      encoding: 'utf8',
      timeout: 15000,
    })

    expect(result.status).not.toBe(0)
    expect(result.stdout).not.toContain('Finder')
  })

  it('lets osascript run when allowAppleEvents is true', () => {
    const result = spawnSync(wrapCommand('osascript -e 1+1', true), {
      shell: true,
      encoding: 'utf8',
      timeout: 15000,
    })

    // Evaluating in-process needs no Apple Event and no TCC grant, so this
    // isolates "the binary is executable again" from "events are permitted".
    expect(result.status).toBe(0)
    expect(result.stdout.trim()).toBe('2')
  })
})

/**
 * Compile a small Objective-C probe, or return undefined where no compiler
 * is installed. `xcode-select -p` is checked first because the /usr/bin
 * shims pop the "install the command line developer tools" dialog when none
 * is, which would hang a CI run.
 */
function buildProbe(
  slug: string,
  source: string,
): { dir: string; binary: string } | undefined {
  if (!isMacOS) return undefined
  const devDir = spawnSync('xcode-select', ['-p'], {
    encoding: 'utf8',
    timeout: 10000,
  })
  if (devDir.status !== 0) return undefined

  const dir = mkdtempSync(path.join(os.tmpdir(), `sandbox-${slug}-probe-`))
  const sourcePath = path.join(dir, 'probe.m')
  const binary = path.join(dir, 'probe')
  writeFileSync(sourcePath, source)
  const compile = spawnSync(
    'xcrun',
    ['clang', '-framework', 'Foundation', '-o', binary, sourcePath],
    { encoding: 'utf8', timeout: 60000 },
  )
  if (compile.status !== 0) {
    rmSync(dir, { recursive: true, force: true })
    return undefined
  }
  return { dir, binary }
}

/**
 * A binary that reaches NSAppleScript through NSClassFromString: it has no
 * static import of the class and is not one of the denied tool paths, so
 * only the OSA component read deny can stop it. The script needs no Apple
 * Event and no TCC grant.
 */
const nsAppleScriptProbe = buildProbe(
  'osa',
  `#import <Foundation/Foundation.h>
#include <stdio.h>
int main(void) {
  @autoreleasepool {
    Class cls = NSClassFromString(@"NSAppleScript");
    NSAppleScript *script = [[cls alloc] initWithSource:@"return 1 + 1"];
    NSDictionary *error = nil;
    NSAppleEventDescriptor *result = [script executeAndReturnError:&error];
    if (result == nil) {
      fprintf(stderr, "OSA_ERROR=%s\\n", [[error description] UTF8String]);
      return 1;
    }
    printf("OSA_RESULT=%s\\n", [[result stringValue] UTF8String]);
    return 0;
  }
}
`,
)

/**
 * A binary that sends a real Apple Event to Finder with no OSA component and
 * no NSAppleScript: it builds the descriptor by hand, which is exactly the
 * route neither the process-exec deny nor the component read deny can reach.
 * Only (deny default) withholding appleevent-send and the appleeventsd
 * mach-lookup stops it, and this probe is what pins that.
 *
 * Send failure and event refusal are deliberately distinguished. Seatbelt
 * makes the send itself fail with -600 (procNotFound), so no reply comes
 * back. A missing TCC automation grant instead lets the send succeed and
 * returns errn -10004 inside the reply — which is what happens under
 * sandbox-exec on a normal desktop, because the sandboxed process is not the
 * one holding the grant. So exit 0 here means "the event reached
 * appleeventsd", whatever TCC then decided.
 */
const rawAppleEventProbe = buildProbe(
  'rawae',
  `#import <Foundation/Foundation.h>
#include <stdio.h>
int main(void) {
  @autoreleasepool {
    NSAppleEventDescriptor *target =
        [NSAppleEventDescriptor descriptorWithBundleIdentifier:@"com.apple.finder"];
    NSAppleEventDescriptor *event =
        [NSAppleEventDescriptor appleEventWithEventClass:'core'
                                                 eventID:'getd'
                                        targetDescriptor:target
                                                returnID:kAutoGenerateReturnID
                                           transactionID:kAnyTransactionID];
    NSAppleEventDescriptor *obj = [NSAppleEventDescriptor recordDescriptor];
    [obj setDescriptor:[NSAppleEventDescriptor descriptorWithTypeCode:'pnam']
            forKeyword:'seld'];
    [event setParamDescriptor:obj forKeyword:'----'];
    NSError *error = nil;
    NSAppleEventDescriptor *reply =
        [event sendEventWithOptions:kAEWaitReply timeout:10.0 error:&error];
    if (reply == nil) {
      fprintf(stderr, "AE_ERROR=%ld\\n", (long)error.code);
      return 1;
    }
    printf("AE_SENT\\n");
    return 0;
  }
}
`,
)

// Outside the sandbox the send must work, or the environment (no GUI
// session, no running Finder) is failing in front of Seatbelt and the
// assertions below would pass for the wrong reason.
const rawAppleEventBaselineWorks =
  rawAppleEventProbe !== undefined &&
  spawnSync(rawAppleEventProbe.binary, { encoding: 'utf8', timeout: 20000 })
    .status === 0

describe.if(rawAppleEventBaselineWorks)(
  'macOS Seatbelt raw Apple Event deny end to end',
  () => {
    afterAll(() => {
      if (rawAppleEventProbe) {
        rmSync(rawAppleEventProbe.dir, { recursive: true, force: true })
      }
    })

    it('blocks a hand-built Apple Event by default', () => {
      const result = spawnSync(wrapCommand(`"${rawAppleEventProbe!.binary}"`), {
        shell: true,
        encoding: 'utf8',
        timeout: 20000,
      })

      expect(result.status).not.toBe(0)
      expect(result.stdout).not.toContain('AE_SENT')
      expect(result.stderr).toContain('AE_ERROR=-600')
    })

    it('lets a hand-built Apple Event through when allowAppleEvents is true', () => {
      const result = spawnSync(
        wrapCommand(`"${rawAppleEventProbe!.binary}"`, true),
        { shell: true, encoding: 'utf8', timeout: 20000 },
      )

      // Asserting the send succeeded, not that Finder answered: see the
      // probe's comment on -10004.
      expect(result.stderr).not.toContain('AE_ERROR=-600')
      expect(result.stdout).toContain('AE_SENT')
    })
  },
)

describe.if(isMacOS && !rawAppleEventBaselineWorks)(
  'macOS Seatbelt raw Apple Event deny end to end (probe unavailable)',
  () => {
    it.skip('skipped: no compiler, or Apple Events do not work outside the sandbox here', () => {})
  },
)

describe.if(isMacOS && nsAppleScriptProbe !== undefined)(
  'macOS Seatbelt OSA component read deny end to end',
  () => {
    afterAll(() => {
      if (nsAppleScriptProbe) {
        rmSync(nsAppleScriptProbe.dir, { recursive: true, force: true })
      }
    })

    it('stops NSAppleScript compiling a script by default', () => {
      const result = spawnSync(wrapCommand(`"${nsAppleScriptProbe!.binary}"`), {
        shell: true,
        encoding: 'utf8',
        timeout: 15000,
      })

      expect(result.status).not.toBe(0)
      expect(result.stdout).not.toContain('OSA_RESULT=')
      expect(result.stderr).toContain('OSA_ERROR=')
    })

    it('lets NSAppleScript run when allowAppleEvents is true', () => {
      const result = spawnSync(
        wrapCommand(`"${nsAppleScriptProbe!.binary}"`, true),
        {
          shell: true,
          encoding: 'utf8',
          timeout: 15000,
        },
      )

      expect(result.status).toBe(0)
      expect(result.stdout.trim()).toBe('OSA_RESULT=2')
    })
  },
)

describe.if(isMacOS && nsAppleScriptProbe === undefined)(
  'macOS Seatbelt OSA component read deny end to end (no compiler)',
  () => {
    it.skip('skipped: no Xcode command line tools to build the NSAppleScript probe', () => {})
  },
)

// `open -g -a Finder .` requires sending an Apple Event to Finder via
// appleeventsd, so it probes the Seatbelt layer. Some CI runners cannot run
// it at all (no usable GUI session / TCC automation grant for the runner
// user) — there the failure sits in front of Seatbelt, so only assert the
// sandbox's behavior when the probe works outside the sandbox.
const openCommand = 'open -g -a Finder .'
const baselineOpenWorks =
  isMacOS &&
  spawnSync(openCommand, { shell: true, encoding: 'utf8', timeout: 15000 })
    .status === 0

describe.if(isMacOS && baselineOpenWorks)(
  'macOS Seatbelt allowAppleEvents end to end',
  () => {
    it('blocks `open` by default', () => {
      const result = spawnSync(wrapCommand(openCommand), {
        shell: true,
        encoding: 'utf8',
        timeout: 15000,
      })

      expect(result.status).not.toBe(0)
    })

    it('allows `open` when allowAppleEvents is true', () => {
      const result = spawnSync(wrapCommand(openCommand, true), {
        shell: true,
        encoding: 'utf8',
        timeout: 15000,
      })

      if (result.status !== 0) {
        // Surface what failed: open's own error plus any Seatbelt denials
        // (deny messages carry the profile's CMD64_ log tag).
        console.error(
          `open probe failed (status ${result.status})\nstdout: ${result.stdout}\nstderr: ${result.stderr}`,
        )
        const denials = spawnSync(
          `log show --last 1m --style compact --predicate 'eventMessage CONTAINS "CMD64_"'`,
          { shell: true, encoding: 'utf8', timeout: 30000 },
        )
        console.error(
          `sandbox denials:\n${(denials.stdout ?? '').slice(-6000)}`,
        )
      }

      expect(result.status).toBe(0)
    })
  },
)

describe.if(isMacOS && !baselineOpenWorks)(
  'macOS Seatbelt allowAppleEvents end to end (environment cannot send Apple Events)',
  () => {
    it.skip('skipped: `open -g -a Finder .` fails outside the sandbox in this environment', () => {})
  },
)
