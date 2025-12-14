import * as esbuild from 'esbuild';
import fs from 'fs';
import path from 'path';

async function build() {
  console.log("⚡ Compiling Kernel (Core) with esbuild...");
  if (!fs.existsSync('dist')) fs.mkdirSync('dist');

  // 1. Build Workers
  console.log("   - Building Pure JS Worker...");
  const pureResult = await esbuild.build({
    entryPoints: ['src/worker/index.ts'],
    bundle: true,
    write: false,
    format: 'iife', // Worker needs to be standalone script or iife for Blob
    minify: true,
    target: 'es2020',
    define: { 'process.env.WASM_ENABLED': '"false"' },
    external: [] // No externals for worker, must bundle everything
  });
  const pureWorkerCode = pureResult.outputFiles[0].text;
  fs.writeFileSync('dist/worker.pure.bundle.js', pureWorkerCode);

  console.log("   - Building Pro (Wasm) Worker...");
  const proResult = await esbuild.build({
    entryPoints: ['src/worker/index.ts'],
    bundle: true,
    write: false,
    format: 'iife',
    minify: true,
    target: 'es2020',
    define: { 'process.env.WASM_ENABLED': '"true"' }
  });
  const proWorkerCode = proResult.outputFiles[0].text;
  fs.writeFileSync('dist/worker.pro.bundle.js', proWorkerCode);

  // 2. Build Core Library (TS -> JS)
  console.log("   - Building Core Library...");
  await esbuild.build({
    entryPoints: ['src/index.ts'],
    bundle: true,
    outfile: 'dist/index.js',
    format: 'esm',
    target: 'es2020',
    external: ['zod'], // Keep deps external for library
    sourcemap: true,
    // We need to inject the worker code strings
    // But since we are building index.ts which EXPORTS them, we can't easily injection-replace 
    // variables that don't exist or are imported.
    // Solution: We will append the worker strings to the output or use a define, 
    // BUT index.ts probably doesn't have them defined.
    // Let's create a virtual module or just append. 
    // Better: Write a 'workers.js' that index.ts imports?
    // Or just append the export statements to the end of dist/index.js like before.
  });

  // 3. Append Worker Strings (The "Embedding" Step)
  // scanText and others are now in index.js (from index.ts).
  // We just need to append the WORKER_CODE constants.
  const workerExports = `
export const WORKER_CODE_PURE = ${JSON.stringify(pureWorkerCode)};
export const WORKER_CODE_PRO = ${JSON.stringify(proWorkerCode)};
`;
  fs.appendFileSync('dist/index.js', workerExports);

  // 4. Generate/Copy Types
  // Since we have TS now, we should ideally use tsc --emitDeclarationOnly
  // For now, we'll assume the user has a d.ts or we rely on the handwritten one + appends
  // Prompt asked to "Define typed events in src/types.ts".
  // Real d.ts generation is best.
  // We'll trust the user/environment to run tsc for types if needed, or just copy a basic one.
  // For v2.0, let's try to generate one if possible, or minimally copy src/index.ts to dist? No.
  // We will write a basic .d.ts that re-exports.
  const dts = `
export * from '../src/index';
export declare const WORKER_CODE_PURE: string;
export declare const WORKER_CODE_PRO: string;
`;
  fs.writeFileSync('dist/index.d.ts', dts);

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
