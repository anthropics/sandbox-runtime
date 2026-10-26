#!/usr/bin/env python3
"""Applies each mutation to the scratch copy, runs the tests, reverts, prints what failed."""
import subprocess, sys, os, re
ROOT = '/root/repos/anthropics/srt-wt/607'
U = 'src/sandbox/sandbox-utils.ts'
M = 'src/sandbox/sandbox-manager.ts'
R = 'src/sandbox/read-deny-glob.ts'
C = 'src/sandbox/sandbox-config.ts'
SPEND = "      spend(dir, known === undefined ? 1 : 0)\n"
FAST_END = "        !positions.matches(fresh, entry.name, '')\n      ) {\n        continue\n      }\n"
BUDGET_WRAP = "    const budget = readGlobBudget(\n      config?.filesystem.denyReadGlobBudget,\n      customConfig?.filesystem?.denyReadGlobBudget,\n    )\n"
MUT = {
 'a  spend(dir,1) always': [(U, SPEND, "      spend(dir, 1)\n")],
 'b  no spend in withType': [(U, "    spend(real, 0)\n", "")],
 'c  budget error not rethrown from the listing catch': [(U, "      if (err instanceof GlobWalkBudgetError) throw err\n", "")],
 'd  no spend after yield': [(U, "    spend(dir, 0)\n", "")],
 'e1 no time check': [(U, "      budget.entries > budget.maxEntries ||\n      performance.now() - budget.startedAt >= budget.timeoutMs\n", "      budget.entries > budget.maxEntries\n")],
 'e2 no entries check': [(U, "      budget.entries > budget.maxEntries ||\n      performance.now() - budget.startedAt >= budget.timeoutMs\n", "      performance.now() - budget.startedAt >= budget.timeoutMs\n")],
 'f  spend below the fast-path continue': [(U, SPEND, ""), (U, FAST_END, FAST_END + SPEND)],
 'g  no budget beneath an anchor': [(M, "{ anchor, budget, listings }", "{ anchor, budget: anchor === undefined ? budget : undefined, listings }")],
 'h  allowRead walks without the budget': [(M, "walkGlobPatternSteps(pattern, { anchor, budget })", "walkGlobPatternSteps(pattern, { anchor })")],
 'i1 no schema parse': [(M, "    FilesystemConfigSchema.shape.denyReadGlobBudget.parse(given, {\n      path: ['filesystem', 'denyReadGlobBudget'],\n    }),\n", "    given,\n")],
 'i2 last of limits only': [(M, "maxEntries: own?.maxEntries ?? session?.maxEntries,", "maxEntries: own?.maxEntries,")],
 'i3 last defined of limits only': [(M, "timeoutMs: own?.timeoutMs ?? session?.timeoutMs,", "timeoutMs: own ? own.timeoutMs : session?.timeoutMs,")],
 'j  budget error unwrapped': [(M, "    if (!(error instanceof GlobWalkBudgetError)) throw error\n", "    throw error\n")],
 'k1 fresh budget per denyRead pattern': [(M, "{ anchor, budget, listings }", "{ anchor, budget: newGlobWalkBudget(budget), listings }")],
 'k2 fresh budget per allowRead pattern': [(M, "walkGlobPatternSteps(pattern, { anchor, budget })", "walkGlobPatternSteps(pattern, { anchor, budget: newGlobWalkBudget(budget) })")],
 'l  read-deny-glob drops the budget': [(R, "    ...opts,\n", "    anchor: opts.anchor,\n    listings: opts.listings,\n")],
 'm  schema not strict': [(C, "      timeoutMs: z.number().int().positive().optional(),\n    })\n    .strict()\n", "      timeoutMs: z.number().int().positive().optional(),\n    })\n")],
 # Extras, for what the list above does not reach.
 'x1 budget kept across the restarts of a wrap': [(M, BUDGET_WRAP, "    const budget = ((globalThis as any).__kept = restarts > 0 ? (globalThis as any).__kept : readGlobBudget(\n      config?.filesystem.denyReadGlobBudget,\n      customConfig?.filesystem?.denyReadGlobBudget,\n    ))\n")],
 'x2 clock not read at an entry already read': [(U, SPEND, "      if (known === undefined) spend(dir, 1)\n")],
 'x3 listings per pattern at the manager': [(M, "{ anchor, budget, listings }", "{ anchor, budget, listings: new Map() }")],
 'x4 clock read every 16th entry': [(U, "      performance.now() - budget.startedAt >= budget.timeoutMs\n    ) {", "      ((read === 0 || budget.entries % 16 === 0) && performance.now() - budget.startedAt >= budget.timeoutMs)\n    ) {")],
 'x5 getFsReadConfig ignores the configured budget': [(M, "  const budget = readGlobBudget(config.filesystem.denyReadGlobBudget)\n", "  const budget = readGlobBudget()\n")],
 'x6 wrap ignores the session budget': [(M, BUDGET_WRAP, "    const budget = readGlobBudget(\n      customConfig?.filesystem?.denyReadGlobBudget,\n    )\n")],
 'x7 wrap ignores its own budget': [(M, BUDGET_WRAP, "    const budget = readGlobBudget(\n      config?.filesystem.denyReadGlobBudget,\n    )\n")],
 'x8 maxEntries need be no integer': [(C, "      maxEntries: z.number().int().positive().optional(),", "      maxEntries: z.number().positive().optional(),")],
 'x9 timeoutMs need not be positive': [(C, "      timeoutMs: z.number().int().positive().optional(),", "      timeoutMs: z.number().int().optional(),")],
 'x12 at the limit is past it': [(U, "      budget.entries > budget.maxEntries ||", "      budget.entries >= budget.maxEntries ||")],
 'x13 allowRead and denyRead each get a budget (wrap)': [(M, "        (pattern, anchor) => expandAllowReadGlob(budget, pattern, anchor),\n      ),\n    )\n    if (expandedAllowRead === REPLACED)", "        (pattern, anchor) => expandAllowReadGlob(newGlobWalkBudget(budget), pattern, anchor),\n      ),\n    )\n    if (expandedAllowRead === REPLACED)")],
 'x14 defaults changed': [(U, "limits.maxEntries ?? 20_000_000", "limits.maxEntries ?? 2_000_000")],
 'x15 error names the spelled pattern wrongly': [(U, "throw new GlobWalkBudgetError(globPath, dir, budget)", "throw new GlobWalkBudgetError(normalizedPattern, dir, budget)")],
}
def sh(cmd):
    return subprocess.run(cmd, shell=True, cwd=ROOT, capture_output=True, text=True)
def main():
    files = sys.argv[1:] or ['test/sandbox/read-deny-glob-bound.test.ts']
    env = 'PATH=/opt/srt-stubs:$PATH'
    for name, edits in MUT.items():
        sh('git checkout -q -- src')
        for path, old, new in edits:
            p = os.path.join(ROOT, path)
            s = open(p).read()
            n = s.count(old)
            if n != 1:
                print(f'!! {name}: {n} matches in {path} for {old[:50]!r}'); break
            open(p, 'w').write(s.replace(old, new))
        else:
            r = sh(f"{env} bun test {' '.join(files)} 2>&1")
            fails = [re.sub(r'\s*\[[\d.]+ms\]$', '', l[len('(fail) '):]) for l in r.stdout.splitlines() if l.startswith('(fail) ')]
            print(f'## {name}: {len(fails)} failing' + ('' if fails else '   <<<<<< SURVIVES'))
            for f in fails: print('     - ' + f[:170])
    sh('git checkout -q -- src')
main()
