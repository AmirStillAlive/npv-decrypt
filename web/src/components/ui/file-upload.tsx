'use client';
import * as React from 'react';
import { FileUp, X } from 'lucide-react';
import { cn, faFileSize } from '../../lib/utils';

export interface FileUploadProps {
  accept?: string;
  maxSize?: number;
  onFile?: (file: File | null) => void;
  hint?: React.ReactNode;
  className?: string;
}

/** ناحیهٔ دریافت فایل: کشیدن و رها کردن یا انتخاب دستی — تک‌فایل. */
export function FileUpload({ accept, maxSize, onFile, hint, className }: FileUploadProps) {
  const [file, setFile] = React.useState<File | null>(null);
  const [over, setOver] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const inputRef = React.useRef<HTMLInputElement>(null);

  function set(next: File | null) {
    if (next && maxSize && next.size > maxSize) {
      setError(`«${next.name}» بزرگ‌تر از ${faFileSize(maxSize)} است.`);
      return;
    }
    setError(null);
    setFile(next);
    onFile?.(next);
  }

  return (
    <div className={cn('space-y-2', className)}>
      <div
        role="button"
        tabIndex={0}
        aria-label="انتخاب فایل کانفیگ"
        onClick={() => inputRef.current?.click()}
        onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && inputRef.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setOver(false);
          set(e.dataTransfer.files?.[0] ?? null);
        }}
        className={cn(
          'flex cursor-pointer flex-col items-center justify-center gap-1.5 rounded-field border border-dashed p-8 text-center transition-colors duration-(--motion) ease-motion',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/60',
          over ? 'border-foreground/60 bg-accent/60' : 'border-input hover:bg-accent/40',
        )}
      >
        <FileUp className="size-5 text-muted-foreground" />
        <p className="text-sm">
          فایل <span dir="ltr" className="font-medium">.npvt</span> را این‌جا رها کنید یا{' '}
          <span className="font-medium underline underline-offset-4">انتخاب کنید</span>
        </p>
        {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
        <input
          ref={inputRef}
          type="file"
          accept={accept}
          className="sr-only"
          onChange={(e) => set(e.target.files?.[0] ?? null)}
        />
      </div>

      {error && (
        <p className="text-xs text-destructive" role="alert">
          {error}
        </p>
      )}

      {file && (
        <ul className="divide-y divide-border rounded-field border border-border">
          <li className="flex items-center gap-2 px-3 py-2 text-xs">
            <span className="flex-1 truncate" dir="auto">
              {file.name}
            </span>
            <span className="text-muted-foreground fa-num">{faFileSize(file.size)}</span>
            <button
              type="button"
              aria-label="حذف"
              onClick={() => set(null)}
              className="cursor-pointer rounded p-0.5 text-muted-foreground hover:text-foreground"
            >
              <X className="size-3.5" />
            </button>
          </li>
        </ul>
      )}
    </div>
  );
}
