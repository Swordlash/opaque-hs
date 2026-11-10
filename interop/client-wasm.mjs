// Runs the client of GHC's WebAssembly backend (test-client/Main.hs,
// compiled) under Node: scripts/client.sh calls it.
//
//   node interop/client-wasm.mjs PROGRAM.wasm JSFFI.mjs [ARGUMENT...]
//
// JSFFI.mjs is the module GHC's post-link.mjs writes for the program: the
// JavaScript the program calls, the client's among it.
//
// The program is a reactor that exports hs_test: a command's main cannot
// wait for a JavaScript promise, since _start has to return before the
// event loop can settle one. Its promise resolves when the program is
// done, and is rejected with what it failed with.
//
// The client is given @serenity-kit/opaque through the global it looks
// for, as a function, the way a page that loads the library late gives it.
// The import is resolved from this file, so from the repository's
// node_modules, wherever the two files above are.
import fs from "node:fs";
import { pathToFileURL } from "node:url";
import { WASI } from "node:wasi";

const [wasmPath, jsffiPath, ...args] = process.argv.slice(2);
if (wasmPath === undefined || jsffiPath === undefined) {
  console.error("usage: node interop/client-wasm.mjs PROGRAM.wasm JSFFI.mjs [ARGUMENT...]");
  process.exit(2);
}

globalThis.opaqueHsSerenity = () => import("@serenity-kit/opaque");

// The program reads no file and no variable of the environment: it gets
// neither. (Given PWD, GHC's runtime would change to that directory, which
// a program with no directory cannot.)
const wasi = new WASI({
  args: [wasmPath, ...args],
  env: {},
  preopens: {},
  version: "preview1",
  returnOnExit: true,
});
const exports = {};
const jsffi = (await import(pathToFileURL(jsffiPath))).default;
const instance = await WebAssembly.instantiate(await WebAssembly.compile(fs.readFileSync(wasmPath)), {
  wasi_snapshot_preview1: wasi.wasiImport,
  ghc_wasm_jsffi: jsffi(exports),
});
Object.assign(exports, instance.exports);
wasi.initialize(instance);
try {
  await instance.exports.hs_test();
} catch (error) {
  console.error(`${wasmPath}: ${error?.message ?? error}`);
  process.exit(1);
}
process.exit(0);
