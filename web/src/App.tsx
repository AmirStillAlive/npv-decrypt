import { useState } from 'react';
import { ArrowLeft, Check, Copy, Download, FileCode2, Github, KeyRound, Lock, ShieldCheck } from 'lucide-react';
import { Button } from './components/ui/button';
import { FileUpload } from './components/ui/file-upload';
import { cn, fa, faNumber } from './lib/utils';

const REPO_URL = 'https://github.com/AmirStillAlive/npv-decrypt';

type Entry = {
  name: string;
  address: string;
  net: string;
  tls: string;
  vmess: string | null;
  json: string;
};

type Result = {
  fileName: string;
  blobCount: number;
  entries: Entry[];
  raw: string;
};

async function decryptFile(file: File): Promise<Result> {
  const text = await file.text();
  const [npv, tables] = await Promise.all([
    import('./lib/npv'),
    import('./lib/npv_tables.json'),
  ]);
  if (!npv.hasTables()) npv.setTables(tables.default);

  const blobs = npv.decryptFileText(text);
  if (!blobs.length) {
    throw new Error('هیچ بلاک قابل رمزگشایی پیدا نشد. فایل `.npvt` است؟');
  }

  const prettyParts = blobs.map((b: Uint8Array) => npv.pretty(b));
  const entries: Entry[] = [];

  for (const part of prettyParts) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(part);
    } catch {
      continue;
    }
    const list = Array.isArray(parsed) ? parsed : [parsed];
    for (const item of list as Record<string, unknown>[]) {
      const profile = (item.v2rayProfile ?? {}) as Record<string, string>;
      entries.push({
        name: String(item.name ?? profile.remarks ?? '').trim() || 'بدون نام',
        address: String(profile.server ? `${profile.server}:${profile.serverPort}` : item.address ?? '—'),
        net: profile.network ?? '—',
        tls: profile.security ?? '—',
        vmess: npv.toVmessLink(item),
        json: JSON.stringify(item, null, 2),
      });
    }
  }

  return {
    fileName: file.name,
    blobCount: blobs.length,
    entries,
    raw: prettyParts.join('\n\n'),
  };
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [done, setDone] = useState(false);
  return (
    <Button
      variant="outline"
      size="sm"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
        } catch {
          /* مرورگر اجازه نداد — بی‌صدا رد می‌شویم */
        }
        setDone(true);
        setTimeout(() => setDone(false), 1500);
      }}
      aria-label={label}
    >
      {done ? <Check className="text-success" /> : <Copy />}
      {done ? 'کپی شد' : label}
    </Button>
  );
}

export default function App() {
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Result | null>(null);

  async function run() {
    if (!file) return;
    setBusy(true);
    setError(null);
    setResult(null);
    // بارگذاری جدول‌ها از حلقهٔ رندر بیرون است
    await new Promise((r) => setTimeout(r, 30));
    try {
      setResult(await decryptFile(file));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'رمزنگاری ناموفق بود.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto flex min-h-screen w-full max-w-3xl flex-col gap-10 px-5 py-12">
      {/* سربرگ */}
      <header className="space-y-3">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Lock className="size-3.5" />
          <span>همه‌چیز در مرورگر شما انجام می‌شود — بدون آپلود به سرور</span>
        </div>
        <h1 className="text-3xl font-bold leading-tight">دیکریپت کانفیگ NPV Tunnel</h1>
        <p className="max-w-prose text-muted-foreground">
          فایل کانفیگ <span dir="ltr" className="font-medium">.npvt</span> را بگذارید تا به JSON خوانا و لینک آمادهٔ ورود تبدیل
          شود. رمزگشایی با جدول‌های white-box کاملاً داخل همین صفحه اجرا می‌شود.
        </p>
      </header>

      {/* ابزار */}
      <section className="rounded-surface border border-border bg-card p-5 shadow-surface">
        <div className="space-y-4">
          <FileUpload
            accept=".npvt"
            maxSize={10 * 1024 * 1024}
            onFile={setFile}
            hint="فقط فرمت .npvt — فایل .npv (نسخهٔ ۵) هنوز پشتیبانی نمی‌شود"
          />
          <div className="flex items-center gap-3">
            <Button onClick={run} disabled={!file || busy}>
              {busy ? 'در حال رمزگشایی…' : 'دیکریپت کن'}
              {!busy && <ArrowLeft />}
            </Button>
            {busy && (
              <span className="text-xs text-muted-foreground">بارگذاری جدول‌های رمز…</span>
            )}
          </div>
          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}
        </div>

        {/* نتیجه */}
        {result && (
          <div className="mt-6 space-y-4 border-t border-border pt-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="text-sm">
                <span dir="auto" className="font-medium">
                  {result.fileName}
                </span>
                <span className="text-muted-foreground">
                  {' '}
                  — {fa(result.blobCount)} بلاک، {fa(result.entries.length)} کانفیگ استخراج شد
                </span>
              </div>
              <div className="flex gap-2">
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() =>
                    downloadText(result.fileName.replace(/\.npvt$/i, '') + '.txt', result.raw)
                  }
                >
                  <Download />
                  دانلود خروجی
                </Button>
              </div>
            </div>

            {result.entries.length > 0 && (
              <ul className="divide-y divide-border rounded-field border border-border">
                {result.entries.map((e, i) => (
                  <li key={i} className="space-y-2 px-3 py-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="min-w-0">
                        <p className="truncate text-sm font-medium" dir="auto">
                          {e.name}
                        </p>
                        <p className="text-xs text-muted-foreground fa-num">
                          <span dir="ltr">{e.address}</span>
                          {' · '}شبکه {e.net}
                          {e.tls !== '—' && e.tls ? ` · ${e.tls}` : ''}
                        </p>
                      </div>
                      {e.vmess && <CopyButton value={e.vmess} label="کپی لینک vmess" />}
                    </div>
                    <details>
                      <summary className="cursor-pointer select-none text-xs text-muted-foreground">
                        نمایش JSON این کانفیگ
                      </summary>
                      <pre
                        dir="ltr"
                        className="mt-2 max-h-64 overflow-auto rounded-field border border-border bg-background p-3 text-xs leading-relaxed"
                      >
                        {e.json}
                      </pre>
                    </details>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </section>

      {/* سه کارت توضیح */}
      <section className="grid gap-4 sm:grid-cols-3">
        <article className="rounded-surface border border-border bg-card p-4 shadow-surface">
          <KeyRound className="mb-2 size-4 text-brand" />
          <h2 className="mb-1 text-sm font-semibold">چطور کار می‌کند؟</h2>
          <p className="text-xs leading-relaxed text-muted-foreground">
            فرمت <span dir="ltr">NPVT1</span> یک AES-128 در حالت CTR است که کلیدش به‌جای متن، به‌صورت جدول‌های
            white-box در خود اپ پیاده شده. همان جدول‌ها این‌جا بازسازی و کی‌استریم تولید می‌شود.
          </p>
        </article>

        <article className="rounded-surface border border-border bg-card p-4 shadow-surface">
          <ShieldCheck className="mb-2 size-4 text-brand" />
          <h2 className="mb-1 text-sm font-semibold">چرا این رمز امن نیست؟</h2>
          <p className="text-xs leading-relaxed text-muted-foreground">
            جدول‌های white-box عمومی‌اند و کلید اصلی هیچ‌جا لازم نیست؛ پس «رمزگذاری» فقط مانع خواندن مستقیم است.
            کانفیگی که می‌گیرید از سرور خودِ سازنده‌اش رد می‌شود.
          </p>
        </article>

        <article className="rounded-surface border border-border bg-card p-4 shadow-surface">
          <FileCode2 className="mb-2 size-4 text-brand" />
          <h2 className="mb-1 text-sm font-semibold">چه فرمت‌هایی؟</h2>
          <p className="text-xs leading-relaxed text-muted-foreground">
            <span dir="ltr">.npvt</span> کامل پشتیبانی می‌شود. فایل <span dir="ltr">.npv</span> با ساختار
            <span dir="ltr"> NPVS</span> نسخهٔ ۵ فعلاً خیر — نسخهٔ پایتونی و سورس در مخزن گیت‌هاب موجود است.
          </p>
        </article>
      </section>

      {/* پاورقی */}
      <footer className="mt-auto flex flex-wrap items-center justify-between gap-3 border-t border-border pt-5 text-xs text-muted-foreground">
        <span className={cn('fa-num')}>
          متن‌باز با پروانهٔ MIT · جدول‌ها از پروژهٔ Pantegnos
        </span>
        <a
          href={REPO_URL}
          target="_blank"
          rel="noreferrer"
          className="inline-flex items-center gap-1.5 underline underline-offset-4 hover:text-foreground"
        >
          <Github className="size-3.5" />
          مخزن گیت‌هاب
        </a>
      </footer>
    </div>
  );
}
