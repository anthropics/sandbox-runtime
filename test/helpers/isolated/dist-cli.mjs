// places.ts, for the built command line tool.
import { setMountPointManifestPlacesForTesting } from '../../../dist/sandbox/bwrap-mount-manifests.js'

setMountPointManifestPlacesForTesting('/nonexistent')
await import('../../../dist/cli.js')
