"""Mutations of the source of sandbox-runtime PR 693. (id, file, old, new)."""

RP = 'src/utils/real-path.ts'
SU = 'src/sandbox/sandbox-utils.ts'
LX = 'src/sandbox/linux-sandbox-utils.ts'
MAC = 'src/sandbox/macos-sandbox-utils.ts'
MGR = 'src/sandbox/sandbox-manager.ts'
GLOB = 'src/sandbox/read-deny-glob.ts'
CFG = 'src/sandbox/sandbox-config.ts'
C = 'vendor/seccomp-src/apply-seccomp.c'

M = []


def m(id_, file, old, new):
    M.append((id_, file, old, new))


# ---------------------------------------------------------------- real-path.ts
m('R01 EILSEQ error carries no path', RP, "      code: 'EILSEQ',\n      path: at,\n", "      code: 'EILSEQ',\n")
m('R02 wayTo never calls watcher.left', RP, '        watcher.left?.(real)\n', '')
m('R03 wayTo calls left at the root too', RP, "if (name === '..' && real !== '') {", "if (name === '..') {")
m('R04 wayTo never calls watcher.link', RP, '    watcher.link?.(next, target)\n', '')
m('R06 never goes on past a missing name', RP, "      names[1] !== '..' ||\n", "      true ||\n")
m('R07 passed names are not recorded', RP, '    passed.push(`${real}/${names[0]}`)\n', '')
m('R08 goes on past a name it could not look for (EACCES)', RP,
  "      names[1] !== '..' ||\n      (notThere as NodeJS.ErrnoException | undefined)?.code === 'EACCES'\n",
  "      names[1] !== '..'\n")
m('R09 rest keeps . and empty names', RP, 'return { real, rest: names, notThere, passed }', 'return { real, rest, notThere, passed }')
m('R10 only one missing name is passed', RP, 'const MAX_MISSING_NAMES_PASSED = 40', 'const MAX_MISSING_NAMES_PASSED = 0')
m('R11 no limit on missing names passed', RP, 'const MAX_MISSING_NAMES_PASSED = 40', 'const MAX_MISSING_NAMES_PASSED = 4000')
m('R12 39 links followed', RP, 'const MAX_LINKS = 40', 'const MAX_LINKS = 39')
m('R13 41 links followed', RP, 'const MAX_LINKS = 40', 'const MAX_LINKS = 41')
m('R14 too many missing names is EIO, not ELOOP', RP, "    { code: 'ELOOP', path: folded },\n  )\n}", "    { code: 'EIO', path: folded },\n  )\n}")
m('R15 U+FFFD in a target is always refused', RP,
  "text.includes('\\uFFFD') && !ask(at, 'buffer').equals(Buffer.from(text))", "text.includes('\\uFFFD')")
m('R16 the watcher is not handed on past a missing name', RP, 'wayTo(onward, watcher)', 'wayTo(onward, passed.length ? undefined : watcher)')

# ------------------------------------------------------------ followLinks
m('F01 path not resolved (relative, . and ..)', SU, "    wayPastMissingNames(path.resolve(p), {", "    wayPastMissingNames(p, {")
m('F02 no second look', SU,
  "  } catch {\n    // Once more: a look can fail in passing (EIO, ESTALE), and what would\n    // follow from that is a directory denied whole.\n    try {\n      way = walk()\n",
  "  } catch (first) {\n    try {\n      throw first\n")
m('F03 a link that is no text is not listed', SU, "      if (code === 'EILSEQ' && at) links.set(at, '')\n", '')
m('F04 ELOOP is could-not-look', SU, "        isAbsenceErrno(err) ||\n        code === 'EILSEQ'", "        (isAbsenceErrno(err) && code !== 'ELOOP') ||\n        code === 'EILSEQ'")
m('F05 ENAMETOOLONG is could-not-look', SU, "        isAbsenceErrno(err) ||\n        code === 'EILSEQ'", "        (isAbsenceErrno(err) && code !== 'ENAMETOOLONG') ||\n        code === 'EILSEQ'")
m('F06 EILSEQ is could-not-look', SU, "        code === 'EILSEQ' ||\n", '')
m('F07 NUL (ERR_INVALID_ARG_VALUE) is could-not-look', SU, "        code === 'EILSEQ' ||\n        code === 'ERR_INVALID_ARG_VALUE'", "        code === 'EILSEQ'")
m('F08 unsearched from the path as written, not where it failed', SU, 'path.dirname(at ?? path.resolve(p))', 'path.dirname(path.resolve(p))')
m('F09 no unsearched where the error has no path', SU, 'path.dirname(at ?? path.resolve(p))', "path.dirname(at ?? '/')")
m('F10 the root can be unsearched (thrown)', SU, "        ...(dir !== '/' && { unsearched: dir }),", "        ...(!nothingCanBeThere && { unsearched: dir }),")
m('F11 EACCES is taken for not-there', SU, "?.code === 'EACCES'\n    ? { links, left, passed,", "?.code === 'NEVER'\n    ? { links, left, passed,")
m('F12 the root can be unsearched (EACCES)', SU, "...(real !== '' && { unsearched: real }) }", "unsearched: real }")
m('F13 end goes on past .. among missing names', SU, "(rest.includes('..') ? rest.slice(0, 1) : rest)", 'rest')
m('F14 end of the root is empty', SU, "          ) || '/',\n      }\n}", "          ),\n      }\n}")
m('F15 any failure is nothing-can-be-there', SU, "      const nothingCanBeThere =\n        isAbsenceErrno(err) ||", "      const nothingCanBeThere =\n        true ||\n        isAbsenceErrno(err) ||")
m('F16 passed is dropped from the answer', SU, "        left,\n        passed,\n        end:", "        left,\n        passed: [],\n        end:")
m('F17 unsearched is the name, not its directory', SU, "path.dirname(at ?? path.resolve(p))", "(at ?? path.resolve(p))")

# ------------------------------------------------------------ linux: which links
m('L01 held outside every write path too', LX, "        isWithinAnyAllowedWritePath(path.dirname(link)) &&\n", '')
m('L02 kernel directories not left out', LX, "        !KERNEL_TOP_LEVEL_DIRS.some(dir => isAtOrUnder(link, dir)) &&\n", '')
m('L03 hidden by tmpfs not left out', LX, " &&\n        !isHiddenByTmpfs(path.dirname(link), 'writes and reads'),", ',')
m('L04 hidden asked of the link, not its directory', LX, "!isHiddenByTmpfs(path.dirname(link), 'writes and reads')", "!isHiddenByTmpfs(link, 'writes and reads')")
m('L05 no pins above held links', LX, "            ...linksToHold.map(link => link.path),\n", '')
m('L06 no pins for left directories', LX, "            ...[...leftOnTheWay].map(dir => `${dir}/.`),\n", '')
m('L07 a left directory itself is not pinned', LX, "[...leftOnTheWay].map(dir => `${dir}/.`)", "[...leftOnTheWay]")
m('L08 pins where nothing is held', LX, "      ...(whyNotHeld === undefined\n        ? [", "      ...(true\n        ? [")
m('L09 mandatory denies are not walked', LX, "const rawDenyPaths = denyPaths.map(asTaken)",
  "const rawDenyPaths = denyPaths.map((p, i) => i < configuredDenyPaths.length ? asTaken(p) : normalizePathForSandbox(p, { literal: true }))")
m('L10 no stand-in for a directory not looked in', LX, "      if (unsearched === undefined) return rawPath\n", "      if (unsearched !== null) return rawPath\n")
m('L11 stand-in without a warning', LX, "; denying ${unsearched} whole instead`,\n        { level: 'warn' },", "; denying ${unsearched} whole instead`,\n        { level: 'info' },")
m('L12 passed names are not denied', LX, "      rawDenyPaths.push(...alsoDenied.map(asTaken))\n", '')
m('L13 resolveSymlinkedDenyPath forgets passed', LX, "    alsoDenied?.push(...way.passed)\n", '')
m('L14 left of a walk is not noted', LX, "    for (const dir of left) leftOnTheWay.add(dir)\n", '')
m('L15 the helper is asked about with no link to hold', LX, "linksToHold.length > 0 ? whyNoLinkIsHeld() : undefined", "whyNoLinkIsHeld()")
m('L16 read denies are not walked', LX, "    ...readDenyPlan().map(entry => entry.normalizedPath),\n    ...(maskedFileBinds", "    ...(maskedFileBinds")
m('L17 masked files are not walked', LX, "    ...(maskedFileBinds ?? []).map(bind => bind.realPath),\n  ]) {\n    const { canonical, resolved }", "  ]) {\n    const { canonical, resolved }")
m('L18 a dangling read deny is not walked', LX, "if (!resolved || canonical !== name) noteLinksTo(name)", "if (canonical !== name) noteLinksTo(name)")
m('L19 every read deny is walked', LX, "if (!resolved || canonical !== name) noteLinksTo(name)", "noteLinksTo(name)")
m('L20 matchedLinks are not walked', LX, "  readConfig?.matchedLinks?.forEach(noteLinksTo)\n", '')
m('L21 only the first link of a walk is noted', LX, "for (const [link, target] of links) linksToDenies.set(link, target)", "for (const [link, target] of [...links].slice(0, 1)) linksToDenies.set(link, target)")

# ------------------------------------------------------------ linux: why not held
m('W01 no_helper not said', LX, "  if (!helperInUse) return 'no_helper'\n", '')
m('W02 holdsLinks false is ignored', LX, "return config.holdsLinks ? undefined : 'told_no'", "return undefined")
m('W03 holdsLinks true is not taken', LX, "  if (config?.holdsLinks !== undefined) {", "  if (config?.holdsLinks === false) {")
m('W04 argv0 helper is looked for', LX, "  const helper = config?.argv0\n    ? null\n    : getApplySeccompBinaryPath(config?.applyPath)", "  const helper = getApplySeccompBinaryPath(config?.applyPath)")
m("W05 the caller's applyPath is read", LX, "if (helper === null || helper === config?.applyPath) return 'not_told'", "if (helper === null) return 'not_told'")
m('W06 any found helper is trusted', LX, "fs.readFileSync(helper).includes('--holds-links')\n      ? undefined", "fs.readFileSync(helper).includes('')\n      ? undefined")
m('W07 unreadable helper is older_helper', LX, "    return 'no_answer'\n", "    return 'older_helper'\n")
m('W08 the found helper is run', LX, "fs.readFileSync(helper).includes('--holds-links')\n      ? undefined", "spawnSync(helper, ['--holds-links']).status === 0\n      ? undefined")
m('W09 unreadable helper is trusted', LX, "    return 'no_answer'\n", "    return undefined\n")
m("W10 the caller's helper is run", LX, "if (helper === null || helper === config?.applyPath) return 'not_told'",
  "if (helper === null) return 'not_told'\n  if (helper === config?.applyPath) return spawnSync(helper, ['--holds-links']).status === 0 ? 'not_told' : 'not_told'")
m('W11 told_no helper is run', LX, "return config.holdsLinks ? undefined : 'told_no'",
  "return config.holdsLinks ? undefined : (config.applyPath && spawnSync(config.applyPath, ['--holds-links']), 'told_no')")

# ------------------------------------------------------------ linux: the words
m('H01 hold words are not quoted', LX,
  "        ? quote(\n            linksToHold.flatMap(link => [\n              '--hold-link',\n              link.path,\n              link.target,\n            ]),\n          )",
  "        ? linksToHold.flatMap(link => [\n              '--hold-link',\n              link.path,\n              link.target,\n            ]).join(' ')")
m('H02 target before path', LX, "              link.path,\n              link.target,\n", "              link.target,\n              link.path,\n")
m('H03 hold words after the command', LX, "if (holdWords !== '') applySeccompPrefix += `${holdWords} `", "if (holdWords !== '') applySeccompPrefix = `${holdWords} ${applySeccompPrefix}`")
m('H04 words handed where not held', LX, "    const holdWords =\n      whyNotHeld === undefined\n", "    const holdWords =\n      true\n")
m('H05 refusal does not count the hold words', LX, "holdWordsBytes: Buffer.byteLength(holdWords, 'utf8'),", "holdWordsBytes: 0,")
m('H06 refusal counts them wrong', LX, "holdWordsBytes: Buffer.byteLength(holdWords, 'utf8'),", "holdWordsBytes: Buffer.byteLength(holdWords, 'utf8') + 1,")
m('H07 refusal speaks of links where there are none', LX, "        mounts.holdWordsBytes > 0\n", "        mounts.holdWordsBytes >= 0\n")
m('H08 empty target dropped from the words', LX, "              link.target,\n            ]),", "              ...(link.target ? [link.target] : []),\n            ]),")

# ------------------------------------------------------------ linux: the list
m('U01 a held link stays listed', LX, "        unheldLinks.delete(link)\n", '')
m('U02 unheld links are not listed', LX, "      unheldLinks.set(link, whyNotHeld)\n", '')
m('U03 forget forgets nothing', LX, "  unheldLinks.clear()\n", '')
m('U04 reset() does not forget', MGR, "  cleanupBwrapMountPoints({ force: true })\n  forgetLinuxUnheldLinks()\n", "  cleanupBwrapMountPoints({ force: true })\n")
m('U05 updateConfig() does not forget', MGR, "  configInstalls++\n  forgetLinuxUnheldLinks()\n", "  configInstalls++\n")
m('U06 no warning for an unheld link', LX, "nothing holds it (${whyNotHeld})`,\n        { level: 'warn' },", "nothing holds it (${whyNotHeld})`,\n        { level: 'info' },")
m('U07 listed before the wrap can throw', LX, "    const holdWords =\n      whyNotHeld === undefined\n",
  "    for (const l of linksToHold) if (whyNotHeld) unheldLinks.set(l.path, whyNotHeld)\n    const holdWords =\n      whyNotHeld === undefined\n")
m('U08 the manager lists none', MGR, "  getLinuxUnheldLinks,\n  getConfig,", "  getLinuxUnheldLinks: () => [],\n  getConfig,")
m('U09 a wrap clears the list of earlier wraps', LX, "    for (const { path: link } of linksToHold) {\n      if (whyNotHeld === undefined) {", "    unheldLinks.clear()\n    for (const { path: link } of linksToHold) {\n      if (whyNotHeld === undefined) {")
m('U10 warning without the reason', LX, "nothing holds it (${whyNotHeld})`", "nothing holds it`")

# ------------------------------------------------------------ manager, glob, config
m('G01 wrap hands no matchedLinks', MGR, "      matchedLinks: [...matchedLinks],\n", '')
m('G02 getFsReadConfig() hands no matchedLinks', MGR, "    ...(matchedLinks.size > 0 && { matchedLinks: [...matchedLinks] }),\n", '')
m('G03 the expansion notes no matched link', GLOB, "    if (walk.symlinks.has(candidate)) opts.matchedLinks?.add(candidate)\n", '')
m('G04 wrap does not ask the expansion for links', MGR,
  "            unlistableDenyDirs,\n            { anchor, listings, matchedLinks },", "            unlistableDenyDirs,\n            { anchor, listings },")
m('G05 getFsReadConfig() does not ask the expansion', MGR,
  "          unlistableDenyDirs,\n          { anchor, listings, matchedLinks },", "          unlistableDenyDirs,\n          { anchor, listings },")
m('G06 the schema has no holdsLinks', CFG, "  holdsLinks: z\n    .boolean()\n    .optional()\n", "  holdsLinksX: z\n    .boolean()\n    .optional()\n")
m('G07 every match is noted, link or not', GLOB, "if (walk.symlinks.has(candidate)) opts.matchedLinks?.add(candidate)", "opts.matchedLinks?.add(candidate)")

# ------------------------------------------------------------ macOS
m('M01 no deny where the links lead', MAC, "    ...(end === undefined ? [] : startingFrom(end, entry)),\n", '')
m('M02 unsearched directory not denied', MAC, "    ...(unsearched === undefined ? [] : [unsearched]).map(toLiteralPathEntry),\n", '')
m('M03 passed names not denied', MAC, "    ...passed.map(toLiteralPathEntry),\n", '')
m('M04 links not kept', MAC, "[...links.keys(), ...left]", "[...left]")
m('M05 left directories not kept', MAC, "[...links.keys(), ...left]", "[...links.keys()]")
m('M06 links among the devices kept', MAC, "    if (isAtOrUnder(stays, '/dev')) continue\n", '')
m('M07 what holds a link is not kept', MAC, "for (const kept of [stays, ...getAncestorDirectories(stays)]) {", "for (const kept of [stays]) {")
m('M08 devices denied (both sides)', MAC, "    canonical === '/' ||\n    isAtOrUnder(canonical, '/dev')\n", "    canonical === '/'\n")
m('M09 the root as a second spelling', MAC, "    canonical === '/' ||\n    isAtOrUnder(canonical, '/dev')\n", "    isAtOrUnder(canonical, '/dev')\n")
m('M10 a pattern is not started from where links lead', MAC, "...(end === undefined ? [] : startingFrom(end, entry)),", "...(end === undefined || entry.glob ? [] : startingFrom(end, entry)),")
m('M11 devices hidden by a read deny', MAC, "  return [entry, ...startingFrom(canonical, entry)]\n",
  "  return canonical === base ? [entry] : [entry, entry.glob ? { glob: true, path: canonical + entry.path.slice(base.length), anchor: canonical } : { glob: false, path: canonical }]\n")
m('M12 mandatory denies are not walked', MAC,
  "    ...macGetMandatoryDenyEntries(allowGitConfig),\n    ...alsoReadAs(config.denyWithinAllow, 'deny'),\n  ].map(entry => ({ entry, ...followLinks(entryBaseDir(entry)) }))",
  "    ...alsoReadAs(config.denyWithinAllow, 'deny'),\n  ].map(entry => ({ entry, ...followLinks(entryBaseDir(entry)) })).concat(macGetMandatoryDenyEntries(allowGitConfig).map(entry => ({ entry, links: new Map(), left: new Set(), passed: [] })))")
m('M13 no read deny where the link leads', MAC, "  return [entry, ...startingFrom(canonical, entry)]\n", "  return [entry]\n")
m('M14 only the first link kept', MAC, "[...links.keys(), ...left]", "[...[...links.keys()].slice(0, 1), ...left]")
m('M15 the deny as written is dropped', MAC, "=> [\n    entry,\n    ...(end === undefined", "=> [\n    ...(end === undefined")

# ------------------------------------------------------------ the C helper
m('C01 not-a-link is not checked', C, '    if (!S_ISLNK(st.st_mode)) {\n        die_holding(path, "not a symbolic link");\n    }\n', '')
m('C02 a longer word passes (length not compared)', C, "(size_t)length != strlen(target) ||\n                    memcmp(says, target, (size_t)length) != 0)", "memcmp(says, target, (size_t)length) != 0)")
m('C03 a shorter word passes (prefix compared)', C, "(size_t)length != strlen(target) ||\n                    memcmp(says, target, (size_t)length) != 0)", "memcmp(says, target, strlen(target)) != 0)")
m('C04 bytes are not compared', C, "(size_t)length != strlen(target) ||\n                    memcmp(says, target, (size_t)length) != 0)", "(size_t)length != strlen(target))")
m('C05 an empty word is compared', C, "if (*target && ((size_t)length", "if (((size_t)length")
m('C06 the word is not compared at all', C, "if (*target && ((size_t)length", "if (0 && ((size_t)length")
m('C07 no remount', C, "    if (mount(NULL, self, NULL, MS_REMOUNT | MS_BIND | flags, NULL) < 0) {\n        die_holding(path, strerror(errno));\n    }\n", '')
m('C08 remount without read-only', C, "unsigned long flags = MS_RDONLY | MS_NOSUID | MS_NODEV;", "unsigned long flags = MS_NOSUID | MS_NODEV;")
m('C09 remount without nosuid', C, "unsigned long flags = MS_RDONLY | MS_NOSUID | MS_NODEV;", "unsigned long flags = MS_RDONLY | MS_NODEV;")
m('C10 remount without nodev', C, "unsigned long flags = MS_RDONLY | MS_NOSUID | MS_NODEV;", "unsigned long flags = MS_RDONLY | MS_NOSUID;")
m('C11 noexec not given again', C, "    if (fs.f_flag & ST_NOEXEC) flags |= MS_NOEXEC;\n", '')
m('C12 nosymfollow not given again', C, "    if (fs.f_flag & ST_NOSYMFOLLOW) flags |= MS_NOSYMFOLLOW;\n", '')
m('C13 no user namespace after the holds', C, "                hold_link(argv[3 * i + 2], argv[3 * i + 3]);\n            }\n            enter_user_namespace();\n", "                hold_link(argv[3 * i + 2], argv[3 * i + 3]);\n            }\n")
m('C14 --holds-links exits 2', C, 'strcmp(argv[1], "--holds-links") == 0) {\n        return 0;', 'strcmp(argv[1], "--holds-links") == 0) {\n        return 2;')
m('C15 with the capability, no link is held', C, "if (links > 0 || unshare(CLONE_NEWPID | CLONE_NEWNS) < 0) {", "if (unshare(CLONE_NEWPID | CLONE_NEWNS) < 0) {")
m('C16 mounts not made private', C, '            if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {\n                die("apply-seccomp: mount(MS_PRIVATE)");\n            }\n', '')
m('C17 only the first link is held', C, "for (int i = 0; i < links; i++) {\n                hold_link", "for (int i = 0; i < 1; i++) {\n                hold_link")
m('C18 no usage error without a command', C, "    if (argc < 3 * links + 2) {", "    if (argc < 2) {")
m('C19 a failed hold exits 0', C, "            path, why);\n    _exit(1);", "            path, why);\n    _exit(0);")
m('C20 a failed hold is only warned of', C, "            path, why);\n    _exit(1);", "            path, why);")
m('C21 nothing is mounted', C, "    if (mount(self, self, NULL, MS_BIND, NULL) < 0) {\n        die_holding(path, strerror(errno));\n    }\n    close(fd);\n", "    close(fd);\n    return;\n")
m('C22 the refusal does not name holdsLinks', C, '%s: %s (seccomp.holdsLinks: false in the "\n            "sandbox configuration holds no link)\\n"', '%s: %s\\n"')
m('C23 the link is followed when opened', C, "    int fd = open(path, O_PATH | O_NOFOLLOW | O_CLOEXEC);\n    if (fd < 0 || fstat", "    int fd = open(path, O_PATH | O_CLOEXEC);\n    if (fd < 0 || fstat")

# ------------------------------------------------------------ added after the first run
HOLD_MAP = "    .map(([link, target]) => ({ path: link, target }))\n"
m('L22 dangling links are not held', LX, HOLD_MAP, "    .filter(([link]) => fs.existsSync(link))\n" + HOLD_MAP)
m('L23 links to directories are not held', LX, HOLD_MAP, "    .filter(([link]) => !fs.statSync(link, { throwIfNoEntry: false })?.isDirectory())\n" + HOLD_MAP)
m('L24 links to devices are not held', LX, HOLD_MAP, "    .filter(([, target]) => !target.startsWith('/dev'))\n" + HOLD_MAP)
m('L25 links to files are not held', LX, HOLD_MAP, "    .filter(([link]) => !fs.statSync(link, { throwIfNoEntry: false })?.isFile())\n" + HOLD_MAP)
m('L26 the deny is walked as written, not normalized', LX, "const unsearched = noteLinksTo(rawPath)", "const unsearched = noteLinksTo(pathPattern)")
m('L27 held only where it leads into a write path', LX, HOLD_MAP,
  "    .filter(([link]) => {\n      try {\n        return isWithinAnyAllowedWritePath(fs.realpathSync(link))\n      } catch {\n        return true\n      }\n    })\n" + HOLD_MAP)
m('M16 /dev itself is denied', MAC, "    isAtOrUnder(canonical, '/dev')\n", "    canonical.startsWith('/dev/')\n")
m('U11 the reason of an earlier wrap stays', LX, "      unheldLinks.set(link, whyNotHeld)\n", "      if (!unheldLinks.has(link)) unheldLinks.set(link, whyNotHeld)\n")
m('C24 the remount follows the link', C, "    fd = open(path, O_PATH | O_NOFOLLOW | O_CLOEXEC);\n    if (fd < 0 || fstatvfs", "    fd = open(path, O_PATH | O_CLOEXEC);\n    if (fd < 0 || fstatvfs")
