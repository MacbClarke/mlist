import { useEffect, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

import type { ListEntry } from "@/types";
import { createSignedFileLink } from "@/api";
import {
    isMarkdownFile,
    isPlainTextFile,
} from "@/lib/fileTypes";
import { useRemoteTextContent } from "@/hooks/useRemoteTextContent";

export function FilePreview({ entry }: { entry: ListEntry }) {
    const [preview, setPreview] = useState({
        path: entry.path,
        url: "",
        error: "",
    });

    useEffect(() => {
        let active = true;
        createSignedFileLink(entry.path)
            .then((payload) => {
                if (!active) return;
                setPreview({ path: entry.path, url: payload.url, error: "" });
            })
            .catch((err) => {
                if (!active) return;
                setPreview({
                    path: entry.path,
                    url: "",
                    error: err instanceof Error ? err.message : "加载预览失败",
                });
            });
        return () => {
            active = false;
        };
    }, [entry.path]);

    const loading = preview.path !== entry.path;

    if (loading) {
        return (
            <div className="text-muted-foreground flex min-h-[45vh] items-center justify-center text-sm">
                正在加载预览...
            </div>
        );
    }

    if (preview.error || !preview.url) {
        return (
            <div className="text-muted-foreground flex min-h-[45vh] items-center justify-center text-sm">
                {preview.error || "加载预览失败"}
            </div>
        );
    }

    return renderPreview(entry, preview.url);
}

function renderPreview(entry: ListEntry, previewUrl: string) {
    const mime = entry.mime ?? "";
    const ext = entry.name.toLowerCase();

    if (isMarkdownFile(entry)) {
        return <MarkdownPreview previewUrl={previewUrl} />;
    }

    if (isPlainTextFile(entry)) {
        return <TextPreview previewUrl={previewUrl} />;
    }

    if (mime.startsWith("image/")) {
        return (
            <div className="bg-muted/30 flex min-h-[65vh] items-center justify-center overflow-hidden rounded-lg border">
                <img
                    src={previewUrl}
                    alt={entry.name}
                    className="h-full w-full object-contain"
                />
            </div>
        );
    }

    if (mime.startsWith("audio/")) {
        return (
            <div className="bg-muted/30 flex min-h-[45vh] items-center justify-center rounded-lg border">
                <audio
                    controls
                    src={previewUrl}
                    className="w-full max-w-2xl px-3"
                >
                    当前浏览器不支持音频播放。
                </audio>
            </div>
        );
    }

    if (mime.startsWith("video/")) {
        return (
            <div className="bg-muted/30 min-h-[65vh] overflow-hidden rounded-lg border">
                <video
                    controls
                    src={previewUrl}
                    className="h-full w-full object-contain"
                >
                    当前浏览器不支持视频播放。
                </video>
            </div>
        );
    }

    if (mime === "application/pdf" || ext.endsWith(".pdf")) {
        return (
            <div className="bg-muted/30 min-h-[80vh] overflow-hidden rounded-lg border">
                <iframe
                    src={previewUrl}
                    title={entry.name}
                    className="h-[80vh] w-full border-0"
                />
            </div>
        );
    }

    return (
        <div className="bg-muted/30 text-muted-foreground flex min-h-[45vh] items-center justify-center rounded-lg border text-sm">
            当前文件类型不支持预览。
        </div>
    );
}

function MarkdownPreview({ previewUrl }: { previewUrl: string }) {
    const { content, loading, error } = useRemoteTextContent(previewUrl);

    if (loading) {
        return (
            <div className="bg-muted/30 text-muted-foreground flex min-h-[45vh] items-center justify-center rounded-lg border text-sm">
                正在加载 Markdown...
            </div>
        );
    }

    if (error) {
        return (
            <div className="bg-muted/30 text-muted-foreground flex min-h-[45vh] items-center justify-center rounded-lg border text-sm">
                {error}
            </div>
        );
    }

    return (
        <div className="bg-muted/30 min-h-[65vh] overflow-hidden rounded-lg border">
            <div className="h-full w-full overflow-auto p-4">
                <article className="text-sm leading-6 [&_a]:text-sky-700 [&_a:hover]:underline [&_blockquote]:border-l-2 [&_blockquote]:border-border [&_blockquote]:pl-4 [&_code]:rounded [&_code]:bg-muted [&_code]:px-1.5 [&_code]:py-0.5 [&_h1]:mt-6 [&_h1]:text-2xl [&_h1]:font-semibold [&_h2]:mt-5 [&_h2]:text-xl [&_h2]:font-semibold [&_h3]:mt-4 [&_h3]:text-lg [&_h3]:font-semibold [&_hr]:my-4 [&_hr]:border-border [&_li]:my-1 [&_ol]:list-decimal [&_ol]:pl-6 [&_p]:my-3 [&_pre]:my-3 [&_pre]:overflow-x-auto [&_pre]:rounded-md [&_pre]:border [&_pre]:bg-slate-900 [&_pre]:p-3 [&_pre]:text-slate-100 [&_table]:my-4 [&_table]:w-full [&_table]:border-collapse [&_td]:border [&_td]:border-border [&_td]:px-2 [&_td]:py-1 [&_th]:border [&_th]:border-border [&_th]:bg-muted/70 [&_th]:px-2 [&_th]:py-1 [&_th]:text-left [&_ul]:list-disc [&_ul]:pl-6">
                    <ReactMarkdown remarkPlugins={[remarkGfm]}>
                        {content}
                    </ReactMarkdown>
                </article>
            </div>
        </div>
    );
}

function TextPreview({ previewUrl }: { previewUrl: string }) {
    const { content, loading, error } = useRemoteTextContent(previewUrl);

    if (loading) {
        return (
            <div className="bg-muted/30 text-muted-foreground flex min-h-[45vh] items-center justify-center rounded-lg border text-sm">
                正在加载文本...
            </div>
        );
    }

    if (error) {
        return (
            <div className="bg-muted/30 text-muted-foreground flex min-h-[45vh] items-center justify-center rounded-lg border text-sm">
                {error}
            </div>
        );
    }

    return (
        <div className="bg-muted/30 min-h-[65vh] overflow-hidden rounded-lg border">
            <pre className="h-full w-full overflow-auto p-4 text-sm leading-6 whitespace-pre-wrap break-words">
                {content}
            </pre>
        </div>
    );
}
