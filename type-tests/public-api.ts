import { z } from 'zod'
import {
  SandboxRuntimeConfigSchema,
  FilesystemConfigSchema,
  type SandboxRuntimeConfig,
} from '../dist/index.js'

// Compile the emitted public declarations without skipLibCheck. Building the
// library alone would not catch an incompatible Zod API in consumer types.
const config: SandboxRuntimeConfig = {
  network: { allowedDomains: [], deniedDomains: [] },
  filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
}
const schema: z.ZodType<SandboxRuntimeConfig> = SandboxRuntimeConfigSchema
const parsed: z.infer<typeof SandboxRuntimeConfigSchema> = schema.parse(config)
const composed = z.object({ filesystem: FilesystemConfigSchema })
composed.parse({ filesystem: parsed.filesystem })
