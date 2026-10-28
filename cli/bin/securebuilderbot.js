#!/usr/bin/env node
// The `securebuilderbot` command. The CLI is TypeScript run from source, as both adapters are:
// tsx (the package's one runtime dependency) loads src/main.ts, which imports the adapters'
// templates and setup functions by relative path from this checkout of the bot. Publishing a
// self-contained package (bundling the adapters) is a follow-up recorded in SPEC-cli.md.
import { tsImport } from "tsx/esm/api";

const { main, processIo } = await tsImport("../src/main.ts", import.meta.url);
process.exitCode = await main(process.argv.slice(2), processIo());
