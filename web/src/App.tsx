import { useState } from 'react';
import { ArrowLeft, Check, Copy, Download, FileJson, Github, Lock } from 'lucide-react';
import { Button } from './components/ui/button';
import { FileUpload } from './components/ui/file-upload';
import { Alert } from './components/ui/alert';
import { Accordion } from './components/ui/accordion';
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

/** ساخت لینک vless از روی outbound استاندارد v2ray */
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

/** ساخت لینک trojan از روی outbound استاندارد v2ray */
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

/** ساخت لینک vmess برای پروفایل‌های ساده بدون v2rayJson */
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

  const fmt = npv.detectFormat(text);
  if (fmt === 'npv') {
    throw new Error('این فایل از نوع .npv است و باز نمی‌شود. لطفا فایل .npvt بدهید.');
  }

  const blobs = npv.decryptFileText(text);
  if (!blobs.length) {
    throw new Error('این فایل شناخته نشد. فقط فایل .npvt قابل قبول است.');
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
      const address = String(profile.server ? `${profile.server}:${profile.serverPort}` : (item.address ?? 'نامشخص'));
      let proto = 'نامشخص';
      let links: BuiltLink[] = [];
      let customJson: string | null = null;
      if (profile.v2rayJson) {
        try {
          const full = JSON.parse(profile.v2rayJson);
          const outs = (full.outbounds ?? []) as Record<string, any>[];
          const proxy = outs.find((o) => o.tag === 'proxy') ?? outs[0];
          if (proxy) {
            proto = String(proxy.protocol ?? 'نامشخص');
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
          /* اگر v2rayJson خراب بود، از روی پروفایل ادامه می‌دهیم */
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
        net: String(profile.network ?? 'نامشخص'),
        tls: String(profile.security ?? 'نامشخص'),
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

/** متن فایل «همه لینک‌ها»: هر خط یک لینک */
function allLinksText(result: Result): string {
  const lines = [`# ${result.fileName} : خروجی npv-decrypt`, ''];
  for (const e of result.entries) {
    lines.push(`# ${e.name} (${e.address})`);
    for (const l of e.links) lines.push(l.value);
    if (e.customJson) lines.push('# کانفیگ JSON کامل را با دکمه JSON همین ردیف بگیرید');
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
          /* اگر مرورگر اجازه نداد، بی‌صدا رد می‌شویم */
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

const FAQ = [
  {
    id: 'how',
    title: 'چطور کار می‌کند؟',
    content:
      'فایل npvt در واقع چند رشته base64 است. هر رشته با AES-128 در حالت CTR رمز شده و کلید آن به شکل جدول‌های white-box داخل خود اپ جاسازی شده است. این صفحه همان جدول‌ها را در خودش دارد و کی‌استریم را داخل مرورگر شما می‌سازد. به همین دلیل برای باز کردن فایل به هیچ کلیدی نیاز نیست.',
  },
  {
    id: 'safe',
    title: 'این رمز امن است؟',
    content:
      'نه. چون جدول‌های رمز عمومی‌اند، هر کسی می‌تواند همین کار را بکند و این رمز فقط جلوی خوانده شدن مستقیم را می‌گیرد. نکته مهم‌تر این است که کانفیگی که از این فایل‌ها بیرون می‌آید به سرور سازنده همان کانفیگ وصل می‌شود، پس حتما بدانید به چه سروری اعتماد می‌کنید.',
  },
  {
    id: 'privacy',
    title: 'فایل من کجا می‌رود؟',
    content:
      'هیچ‌جا. فایل فقط با FileReader داخل همین صفحه خوانده می‌شود و صفحه هیچ درخواستی برای آن به هیچ سروری نمی‌فرستد. می‌توانید اینترنت را قطع کنید و باز هم فایل را باز کنید.',
  },
];

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
    // بارگذاری جدول‌ها از حلقه رندر بیرون است
    await new Promise((r) => setTimeout(r, 30));
    try {
      const { result } = await decryptFile(file);
      setResult(result);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'رمزگشایی ناموفق بود.');
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
          <span>همه‌چیز در مرورگر شما انجام می‌شود و فایل به هیچ سروری فرستاده نمی‌شود</span>
        </div>
        <h1 className="text-3xl font-bold leading-tight">دیکریپت کانفیگ NPV Tunnel</h1>
        <p className="max-w-prose text-muted-foreground">
          فایل کانفیگ <span dir="ltr" className="font-medium">.npvt</span> را بگذارید تا به JSON خوانا و لینک آماده ورود تبدیل
          شود. رمزگشایی با جدول‌های white-box کاملا داخل همین صفحه اجرا می‌شود.
        </p>
      </header>

      {/* ابزار */}
      <section className="rounded-surface border border-border bg-card p-5 shadow-surface">
        <div className="space-y-4">
          <FileUpload
            accept=".npvt"
            maxSize={10 * 1024 * 1024}
            onFile={setFile}
            hint="فایل با پسوند .npvt"
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
            <Alert variant="destructive" title="خطا">
              {error}
            </Alert>
          )}
        </div>

        {/* نتیجه */}
        {result && (
          <div className="mt-6 space-y-4 border-t border-border pt-5">
            <Alert variant="success" title={result.fileName}>
              {fa(result.blobCount)} بلاک و {fa(result.entries.length)} کانفیگ استخراج شد.
            </Alert>
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
                دانلود همه لینک‌ها
              </Button>
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
                        {e.tls !== 'نامشخص' && e.tls ? ` · ${e.tls}` : ''}
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
                      <p className="text-xs text-warning">لینک قابل ساخت نیست. خروجی JSON را ببینید.</p>
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

      {/* پرسش‌های پرتکرار */}
      <section className="space-y-3">
        <h2 className="text-sm font-semibold text-muted-foreground">راهنما</h2>
        <Accordion items={FAQ} />
      </section>

      {/* پاورقی */}
      <footer className="mt-auto flex flex-wrap items-center justify-between gap-3 border-t border-border pt-5 text-xs text-muted-foreground">
        <span className={cn('fa-num')}>
          متن‌باز با پروانه MIT و جدول‌های پروژه Pantegnos
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
