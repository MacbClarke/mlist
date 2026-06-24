import type { ListEntry } from "@/types";

export function fileExtension(name: string): string {
    const idx = name.lastIndexOf(".");
    if (idx === -1 || idx === name.length - 1) return "";
    return name.slice(idx + 1).toLowerCase();
}

export function isMarkdownFile(entry: ListEntry): boolean {
    const mime = (entry.mime ?? "").toLowerCase();
    if (
        mime === "text/markdown" ||
        mime === "text/x-markdown" ||
        mime.endsWith("+markdown")
    ) {
        return true;
    }
    return ["md", "markdown", "mdown", "mkd", "mkdn", "mdx"].includes(
        fileExtension(entry.name),
    );
}

export function isPlainTextFile(entry: ListEntry): boolean {
    const mime = (entry.mime ?? "").toLowerCase();
    if (mime === "text/plain") return true;
    return ["txt", "text", "log"].includes(fileExtension(entry.name));
}

export function isImageFile(entry: ListEntry): boolean {
    const mime = entry.mime ?? "";
    if (mime.startsWith("image/")) return true;
    return [
        "jpg",
        "jpeg",
        "png",
        "gif",
        "webp",
        "bmp",
        "svg",
        "avif",
        "heic",
        "heif",
    ].includes(fileExtension(entry.name));
}

export function isAudioFile(entry: ListEntry): boolean {
    const mime = entry.mime ?? "";
    if (mime.startsWith("audio/")) return true;
    return ["mp3", "flac", "aac", "m4a", "ogg", "wav", "opus", "wma"].includes(
        fileExtension(entry.name),
    );
}

export function isVideoFile(entry: ListEntry): boolean {
    const mime = entry.mime ?? "";
    if (mime.startsWith("video/")) return true;
    return [
        "mp4",
        "mkv",
        "mov",
        "avi",
        "wmv",
        "webm",
        "m4v",
        "ts",
        "m2ts",
    ].includes(fileExtension(entry.name));
}
