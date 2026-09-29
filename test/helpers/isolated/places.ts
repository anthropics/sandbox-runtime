import { setMountPointManifestPlacesForTesting } from '../../../src/sandbox/bwrap-mount-manifests.js'

// The first places the mount point manifests are kept in follow from the user
// id, so no environment keeps a test out of the ones the user's own processes
// keep. Whatever loads this looks for them under a root that is not there, finds
// none, and goes by $XDG_RUNTIME_DIR and the temp dir, which a test can give it.
// The preload loads it for the test process. A child process loads the library
// through one of the modules beside this one.
setMountPointManifestPlacesForTesting('/nonexistent')
