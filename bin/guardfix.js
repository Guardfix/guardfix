#!/usr/bin/env node
import { main } from "../src/cli.js";

main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (e) => {
  console.error(`guardfix: ${e.message || e}`);
  process.exitCode = 2;
});
