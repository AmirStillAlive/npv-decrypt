import { useState } from 'react';
import { ArrowLeft, Check, Copy, Download, FileCode2, FileJson, Github, KeyRound, Lock, ShieldCheck } from 'lucide-react';
import { Button } from './components/ui/button';
import { FileUpload } from './components/ui/file-upload';
import { downloadText } from './lib/npv';
import { cn, fa } from './lib/utils';

const REPO_URL = 'https://github.com/AmirStillAlive/npv-decrypt';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

type BuiltLink = {
  kind: 'vmess' | 'vless' | 'trojan';
  label: string;
  value: string;
};

type Entry = {
  name: string;
  address: string;
  proto: string;
  net: string;
  tls: string;
  links: BuiltLink[];
  customJson: string | null;
  json: string;
};

type Result = {
  fileName: string;
  blobCount: number;
  entries: Entry[];
  raw: string;
};

function b64encodeUnicode(s: string): string {
  return btoa(unescape(encodeURIComponent(s)));
}

/** فایل‌نام امن برای دانلود JSON هر کانفیگ */
function safeName(s: string): string {
  return s.replace(/[\\/:*?"<>|\n\r\t]/g, '_').trim().slice(0, 80) || 'config';
}

/** vless://uuid@host:port?params#remark — از روی outbound استاندارد v2ray */
function buildVlessLink(ob: Record<string, any>, remark: string): BuiltLink | null {
  try {
    const ss = ob.streamSettings ?? {};
    const st = ob.settings ?? {};
    const vnext = (st.vnext ?? [])[0] ?? {};
    const user = (vnext.users ?? [])[0] ?? {};
    if (!user.id || !vnext.address) return null;
    const net = ss.network ?? 'tcp';
    const sec = ss.security ?? 'none';
    const tls = ss.tlsSettings ?? {};
    const q = new URLSearchParams();
    q.set('security', sec === 'tls' ? 'tls' : 'none');
    q.set('encryption', user.encryption ?? 'none');
    if (net === 'ws') {
      const w = ss.wsSettings ?? {};
      q.set('type', 'ws');
      if (w.path) q.set('path', w.path);
      const host = (w.headers && w.headers.Host) || tls.serverName || '';
      if (host) q.set('host', host);
    } else if (net === 'xhttp') {
      const x = ss.xhttpSettings ?? {};
      q.set('type', 'xhttp');
      if (x.path) q.set('path', x.path);
      if (x.host) q.set('host', x.host);
      if (x.mode) q.set('mode', x.mode);
    } else {
      q.set('type', net);
    }
    if (sec === 'tls') {
      if (tls.serverName) q.set('sni', tls.serverName);
      if (tls.fingerprint) q.set('fp', tls.fingerprint);
      const alpn = Array.isArray(tls.alpn) ? tls.alpn.join(',') : tls.alpn;
      if (alpn) q.set('alpn', alpn);
      if (tls.allowInsecure) q.set('allowInsecure', '1');
    }
    return {
      kind: 'vless',
      label: 'vless',
      value: `vless://${user.id}@${vnext.address}:${vnext.port ?? 443}?${q.toString()}#${encodeURIComponent(remark)}`,
    };
  } catch {
    return null;
  }
}

/** trojan://password@host:port?params#remark — از روی outbound استاندارد v2ray */
function buildTrojanLink(ob: Record<string, any>, remark: string): BuiltLink | null {
  try {
    const ss = ob.streamSettings ?? {};
    const st = ob.settings ?? {};
    const srv = (st.servers ?? [])[0] ?? {};
    if (!srv.password || !srv.address) return null;
    const net = ss.network ?? 'tcp';
    const sec = ss.security ?? 'none';
    const tls = ss.tlsSettings ?? {};
    const q = new URLSearchParams();
    if (net === 'ws') {
      const w = ss.wsSettings ?? {};
      q.set('type', 'ws');
      if (w.path) q.set('path', w.path);
      const host = (w.headers && w.headers.Host) || '';
      if (host) q.set('host', host);
    } else {
      q.set('type', net);
    }
    q.set('security', sec === 'tls' ? 'tls' : 'none');
    if (sec === 'tls') {
      if (tls.serverName) q.set('sni', tls.serverName);
      if (tls.fingerprint) q.set('fp', tls.fingerprint);
      const alpn = Array.isArray(tls.alpn) ? tls.alpn.join(',') : tls.alpn;
      if (alpn) q.set('alpn', alpn);
      if (tls.allowInsecure) q.set('allowInsecure', '1');
    }
    return {
      kind: 'trojan',
      label: 'trojan',
      value: `trojan://${encodeURIComponent(String(srv.password))}@${srv.address}:${srv.port ?? 443}?${q.toString()}#${encodeURIComponent(remark)}`,
    };
  } catch {
    return null;
  }
}

/** vmess://... — برای پروفایل‌های سادهٔ بدون v2rayJson */
function buildVmessLink(item: Record<string, any>): BuiltLink | null {
  const p = (item.v2rayProfile ?? {}) as Record<string, any>;
  if (!p.password || !p.server) return null;
  const inner = {
    v: '2',
    ps: String(item.name ?? p.remarks ?? '').trim(),
    add: p.server,
    port: String(p.serverPort),
    id: p.password,
    aid: '0',
    scy: p.method && String(p.method).length < 32 ? p.method : 'auto',
    net: p.network || 'tcp',
    type: p.headerType || 'none',
    host: p.host || '',
    path: p.path || '',
    tls: p.security === 'tls' ? 'tls' : '',
    sni: p.sni || '',
    fp: p.fingerPrint || '',
    alpn: p.alpn || '',
  };
  return { kind: 'vmess', label: 'vmess', value: 'vmess://' + b64encodeUnicode(JSON.stringify(inner)) };
}

/** لینک جایگزین از روی فیلدهای پروفایل، وقتی v2rayJson نیست */
function buildProfileLink(item: Record<string, any>): BuiltLink | null {
  const p = (item.v2rayProfile ?? {}) as Record<string, any>;
  if (!p.server || !p.serverPort) return null;
  const remark = String(item.name ?? p.remarks ?? '').trim();
  const pw = String(p.password ?? '');
  if (pw && !UUID_RE.test(pw) && (p.security === 'tls' || p.sni)) {
    const q = new URLSearchParams();
    q.set('type', p.network || 'ws');
    if (p.path) q.set('path', p.path);
    if (p.host) q.set('host', p.host);
    q.set('security', p.security === 'tls' ? 'tls' : 'none');
    if (p.sni) q.set('sni', p.sni);
    if (p.fingerPrint) q.set('fp', p.fingerPrint);
    if (p.alpn) q.set('alpn', p.alpn);
    if (p.insecure) q.set('allowInsecure', '1');
    return {
      kind: 'trojan',
      label: 'trojan',
      value: `trojan://${encodeURIComponent(pw)}@${p.server}:${p.serverPort}?${q.toString()}#${encodeURIComponent(remark)}`,
    };
  }
  return buildVmessLink(item);
}

async function decryptFile(file: File): Promise<{ result: Result; npv: any }> {
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
    for (const item of list as Record<string, any>[]) {
      const profile = (item.v2rayProfile ?? {}) as Record<string, any>;
      const name = String(item.name ?? profile.remarks ?? '').trim() || 'بدون نام';
      const address = String(profile.server ? `${profile.server}:${profile.serverPort}` : item.address ?? '—');
      let proto = '—';
      let links: BuiltLink[] = [];
      let customJson: string | null = null;
      if (profile.v2rayJson) {
        try {
          const full = JSON.parse(profile.v2rayJson);
          const outs = (full.outbounds ?? []) as Record<string, any>[];
          const proxy = outs.find((o) => o.tag === 'proxy') ?? outs[0];
          if (proxy) {
            proto = String(proxy.protocol ?? '—');
            const b =
              proxy.protocol === 'vless'
                ? buildVlessLink(proxy, name)
                : proxy.protocol === 'trojan'
                  ? buildTrojanLink(proxy, name)
                  : null;
            if (b) links.push(b);
          }
          customJson = JSON.stringify(full, null, 2);
        } catch {
          /* v2rayJson خراب — می‌رویم سراغ پروفایل */
        }
      }
      if (!links.length) {
        const b = buildProfileLink(item);
        if (b) {
          links.push(b);
          proto = b.kind;
        }
      }
      entries.push({
        name,
        address,
        proto,
        net: String(profile.network ?? '—'),
        tls: String(profile.security ?? '—'),
        links,
        customJson,
        json: JSON.stringify(item, null, 2),
      });
    }
  }

  return {
    npv,
    result: {
      fileName: file.name,
      blobCount: blobs.length,
      entries,
      raw: prettyParts.join('\n\n'),
    },
  };
}

/** متن فایل «همهٔ لینک‌ها» — یک لینک در هر خط */
function allLinksText(result: Result): string {
  const lines = [`# ${result.fileName} — خروجی npv-decrypt`, ''];
  for (const e of result.entries) {
    lines.push(`# ${e.name} (${e.address})`);
    for (const l of e.links) lines.push(l.value);
    if (e.customJson) lines.push(`# + کانفیگ JSON کامل در دکمهٔ JSON همین ردیف`);
    lines.push('');
  }
  return lines.join('\n');
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
      const { result } = await decryptFile(file);
      setResult(result);
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
              <div className="flex flex-wrap gap-2">
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() =>
                    downloadText(result.fileName.replace(/\.npvt$/i, '') + '.txt', result.raw)
                  }
                >
                  <Download />
                  دانلود JSON خام
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() =>
                    downloadText(result.fileName.replace(/\.npvt$/i, '') + '-links.txt', allLinksText(result))
                  }
                >
                  <Download />
                  دانلود همهٔ لینک‌ها
                </Button>
              </div>
            </div>

            {result.entries.length > 0 && (
              <ul className="divide-y divide-border rounded-field border border-border">
                {result.entries.map((e, i) => (
                  <li key={i} className="space-y-3 px-3 py-3">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium" dir="auto">
                        {e.name}
                      </p>
                      <p className="text-xs text-muted-foreground fa-num">
                        <span dir="ltr">{e.address}</span>
                        {' · '}
                        <span dir="ltr">{e.proto}</span>
                        {' · '}شبکه {e.net}
                        {e.tls !== '—' && e.tls ? ` · ${e.tls}` : ''}
                      </p>
                    </div>

                    {/* لینک‌های قابل استفاده */}
                    {e.links.length > 0 ? (
                      <div className="space-y-2">
                        {e.links.map((l, j) => (
                          <div key={j} className="flex items-center gap-2">
                            <span
                              dir="ltr"
                              className="rounded-field border border-border bg-background px-2 py-0.5 font-mono text-[11px] text-brand"
                            >
                              {l.label}
                            </span>
                            <code
                              dir="ltr"
                              className="min-w-0 flex-1 truncate rounded-field border border-border bg-background px-2 py-1 text-[11px]"
                            >
                              {l.value.slice(0, 80)}…
                            </code>
                            <CopyButton value={l.value} label={`کپی ${l.label}`} />
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-xs text-warning">لینک قابل ساخت نیست — خروجی JSON را ببینید.</p>
                    )}

                    <div className="flex flex-wrap gap-2">
                      {e.customJson && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => downloadText(`${safeName(e.name)}.json`, e.customJson!)}
                        >
                          <FileJson />
                          دانلود JSON کانفیگ
                        </Button>
                      )}
                      <details className="w-full">
                        <summary className="cursor-pointer select-none text-xs text-muted-foreground">
                          نمایش JSON کامل این کانفیگ
                        </summary>
                        <pre
                          dir="ltr"
                          className="mt-2 max-h-64 overflow-auto rounded-field border border-border bg-background p-3 text-xs leading-relaxed"
                        >
                          {e.json}
                        </pre>
                      </details>
                    </div>
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
