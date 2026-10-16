import pkg from '../../package.json' with { type: 'json' }

/**
 * The version from this package's own package.json. A static import, as in
 * the CLI's `--version`, so a single-file build (`bun build --compile`)
 * embeds it instead of looking for a package.json beside the binary, and so
 * it is correct for an npm install, a global install, and an in-tree build
 * alike. `process.env.npm_package_version` is only set under an npm script,
 * which is never the case for an installed `srt` binary.
 */
export function getPackageVersion(): string {
  return pkg.version
}
