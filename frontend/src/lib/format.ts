export function formatBytes(bytes: number, fractionDigits?: number): string {
    if (bytes < 1024) {
        return fractionDigits == null
            ? `${bytes} B`
            : `${bytes.toFixed(fractionDigits)} B`;
    }
    const units = ["KB", "MB", "GB", "TB"];
    let size = bytes / 1024;
    let unit = 0;
    while (size >= 1024 && unit < units.length - 1) {
        size /= 1024;
        unit += 1;
    }
    return `${size.toFixed(fractionDigits ?? 1)} ${units[unit]}`;
}

export function formatRange(
    start: number | null | undefined,
    end: number | null | undefined,
): string {
    if (typeof start !== "number" || typeof end !== "number") return "--";
    return `${formatBytes(start)}-${formatBytes(end)}`;
}

export function formatDate(unixSeconds: number): string {
    return new Date(unixSeconds * 1000).toLocaleString();
}
