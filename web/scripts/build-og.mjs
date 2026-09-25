// تولید تصویر پیش‌نمایش شبکه‌های اجتماعی (og.png) از روی web/og/og.html
// با Chrome/Edge در حالت headless. نیازی به هیچ وابستگی npm نیست.
//
//   node web/scripts/build-og.mjs
//
// خروجی: web/public/og.png و web/public/apple-touch-icon.png

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, statSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const webRoot = resolve(here, '..');
const srcHtml = resolve(webRoot, 'og/og.html');
const srcIcon = resolve(webRoot, 'og/icon.html');
const outDir = resolve(webRoot, 'public');

/** مسیر مرورگر روی ویندوز؛ اولین گزینه‌ای که نصب باشد. */
function findBrowser() {
  const roots = [
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  ];
  const found = roots.filter((p) => existsSync(p));
  if (!found.length) {
    throw new Error('Chrome یا Edge پیدا نشد. مسیر مرورگر را به BROWSER_PATH بدهید.');
  }
  return found[0];
}

const browser = process.env.BROWSER_PATH || findBrowser();
mkdirSync(outDir, { recursive: true });

/** یک اسکرین‌شات headless می‌گیرد. */
function shoot(outFile, width, height) {
  execFileSync(
    browser,
    [
      '--headless=new',
      '--disable-gpu',
      '--hide-scrollbars',
      '--force-device-scale-factor=1',
      // فونت وب از CDN لازم است؛ به همین دلیل این اسکریپت به اینترنت نیاز دارد
      '--virtual-time-budget=8000',
      `--window-size=${width},${height}`,
      `--screenshot=${outFile}`,
      pathToFileURL(srcHtml).href,
    ],
    { stdio: 'ignore' },
  );
  const { size } = statSync(outFile);
  console.log(`  ${outFile.replace(webRoot + '\\', '')}  (${width}x${height}, ${(size / 1024).toFixed(1)} KB)`);
}

console.log(`مرورگر: ${browser}`);
console.log('در حال ساخت تصاویر:');

// تصویر اصلی پیش‌نمایش لینک (نسبت 1200x630 استاندارد OG)
shoot(resolve(outDir, 'og.png'), 1200, 630);

// apple-touch-icon از روی همان SVG قفل، با پس‌زمینه گرافیت
execFileSync(
  browser,
  [
    '--headless=new',
    '--disable-gpu',
    '--hide-scrollbars',
    '--force-device-scale-factor=1',
    '--virtual-time-budget=3000',
    '--window-size=180,180',
    `--screenshot=${resolve(outDir, 'apple-touch-icon.png')}`,
    pathToFileURL(srcIcon).href,
  ],
  { stdio: 'ignore' },
);
const iconSize = statSync(resolve(outDir, 'apple-touch-icon.png')).size;
console.log(
  `  public\\apple-touch-icon.png  (180x180, ${(iconSize / 1024).toFixed(1)} KB)`,
);

console.log('تمام شد.');
