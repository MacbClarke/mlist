export function isAdminPath(pathname: string): boolean {
    return normalizePath(pathname) === "_mlist/admin";
}

export function normalizePath(path: string): string {
    return path
        .trim()
        .replace(/^\/+/, "")
        .replace(/\/+$/, "")
        .split("/")
        .filter((segment) => segment.length > 0)
        .join("/");
}

export function normalizeOptionalPath(path: string | null | undefined): string | null {
    if (path == null) return null;
    const normalized = normalizePath(path);
    return normalized || null;
}

export function parentPathOf(path: string): string {
    const normalized = normalizePath(path);
    if (!normalized) return "";
    const parts = normalized.split("/");
    parts.pop();
    return parts.join("/");
}

export function pathFromLocation(pathname: string): string {
    const normalized = normalizePath(pathname);
    if (!normalized) return "";
    return normalized
        .split("/")
        .map((segment) => {
            try {
                return decodeURIComponent(segment);
            } catch {
                return segment;
            }
        })
        .join("/");
}

export function browserPath(relativePath: string): string {
    if (!relativePath) return "/";
    return `/${relativePath
        .split("/")
        .map((segment) => encodeURIComponent(segment))
        .join("/")}`;
}

export function syncBrowserState(
    relativePath: string,
    previewPath: string | null,
    replace: boolean,
) {
    if (typeof window === "undefined") return;
    const normalizedPreview = normalizeOptionalPath(previewPath);
    const target = browserPath(normalizedPreview ?? relativePath);
    const current = window.location.pathname;
    if (current === target) return;
    if (replace) {
        window.history.replaceState(null, "", target);
        return;
    }
    window.history.pushState(null, "", target);
}

export function toAbsoluteUrl(url: string): string {
    if (typeof window === "undefined") return url;
    return new URL(url, window.location.origin).toString();
}
