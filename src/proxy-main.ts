#!/usr/bin/env node
// Standalone entry for the proxy-only mode: `srt-proxy <flags>`.
import { runProxyCli } from './proxy-cli.js'

void runProxyCli(process.argv.slice(2))
