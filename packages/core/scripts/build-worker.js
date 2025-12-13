import * as esbuild from 'esbuild';
import fs from 'fs';
import path from 'path';

async function build() {
  console.log("⚡ Compiling Kernel (Core) with esbuild...");
  if (!fs.existsSync('dist')) fs.mkdirSync('dist');

  // 1. Build Workers
  console.log("   - Building Pure JS Worker...");
  const pureResult = await esbuild.build({
    entryPoints: ['src/worker/index.js'],
    bundle: true,
    write: false,
    format: 'esm',
    minify: true,
    target: 'es2020',
    define: { 'process.env.WASM_ENABLED': '"false"' },
    external: ['../core/repair_wasm.js']
  });
  const pureWorkerCode = pureResult.outputFiles[0].text;
  // We save the bundle for debugging or alternative usage
  fs.writeFileSync('dist/worker.pure.bundle.js', pureWorkerCode);

  console.log("   - Building Pro (Wasm) Worker...");
  const proResult = await esbuild.build({
    entryPoints: ['src/worker/index.js'],
    bundle: true,
    write: false,
    format: 'esm',
    minify: true,
    target: 'es2020',
    define: { 'process.env.WASM_ENABLED': '"true"' }
  });
  const proWorkerCode = proResult.outputFiles[0].text;
  fs.writeFileSync('dist/worker.pro.bundle.js', proWorkerCode);

  // 2. Copy Core Files
  copyAndFix('src/core/scanner.js', 'dist/scanner.js');
  copyAndFix('src/core/repair.js', 'dist/repair.js');
  copyAndFix('src/core/registry.js', 'dist/registry.js');
  copyAndFix('src/schema/SchemaEngine.js', 'dist/SchemaEngine.js');

  // 3. Generate index.js (Kernel Entry)
  const indexContent = `/**
 * @ai-guard/core
 * Kernel Logic & Workers
 */
export const WORKER_CODE_PURE = ${JSON.stringify(pureWorkerCode)};
export const WORKER_CODE_PRO = ${JSON.stringify(proWorkerCode)};

export { scanText } from './scanner.js';
export { repairJSON, extractJSON } from './repair.js';
export { registerProfile, getProfile } from './registry.js';
export { SchemaEngine } from './SchemaEngine.js';
`;

  fs.writeFileSync('dist/index.js', indexContent);

  // 4. Generate Types
  if (fs.existsSync('src/index.d.ts')) {
    let dts = fs.readFileSync('src/index.d.ts', 'utf8');
    // Simple append for now
    dts += `
export declare const WORKER_CODE_PURE: string;
export declare const WORKER_CODE_PRO: string;
`;
    fs.writeFileSync('dist/index.d.ts', dts);
  } else {
    const dts = `
export declare const WORKER_CODE_PURE: string;
export declare const WORKER_CODE_PRO: string;
export declare function scanText(text: string): any;
export declare function repairJSON(text: string): any;
export declare function extractJSON(text: string): any;
export declare function registerProfile(name: string, profile: any): void;
export declare function getProfile(name: string): any;
export class SchemaEngine { constructor(schema: any); validate(data: any): any; }
`;
    fs.writeFileSync('dist/index.d.ts', dts);
  }

  console.log("✅ Core Build Complete.");
}

function copyAndFix(src, dest) {
  if (fs.existsSync(src)) {
    let content = fs.readFileSync(src, 'utf8');
    // Fix relative imports if needed (e.g. if SchemaEngine imported from ../core)
    // But since we flatten, generally we want to ensure imports are ./filename.js
    content = content.replace(/from\s+['"]\.\.\/core\/([^'"]+)['"]/g, "from './$1'");
    // Also strict zod import check? No, Zod is external dependency.
    fs.writeFileSync(dest, content);
  } else {
    console.warn(`Warning: Source file ${src} not found.`);
  }
}

build().catch((e) => {
  console.error(e);
  process.exit(1);
});
