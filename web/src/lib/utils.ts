/** ابزارهای کمکی فارسی: cn، اعداد فارسی و حجم فایل. */

export function cn(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(' ');
}

/** عدد لاتین به ارقام فارسی (برای لایه نمایش) */
export function fa(n: number | string): string {
  return String(n).replace(/[0-9]/g, (d) => '۰۱۲۳۴۵۶۷۸۹'[Number(d)]);
}

/** جداکنندهٔ هزارگان فارسی + ارقام فارسی */
export function faNumber(n: number): string {
  return fa(n.toLocaleString('en-US').replace(/,/g, '٬'));
}

/** حجم فایل با واحد فارسی: «۱۲ کیلوبایت» */
export function faFileSize(bytes: number): string {
  if (bytes < 1024) return `${fa(bytes)} بایت`;
  if (bytes < 1024 * 1024) return `${fa((bytes / 1024).toFixed(1))} کیلوبایت`;
  return `${fa((bytes / (1024 * 1024)).toFixed(1))} مگابایت`;
}
