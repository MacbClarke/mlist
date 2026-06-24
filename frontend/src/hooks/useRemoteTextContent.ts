import { useEffect, useState } from "react";

export function useRemoteTextContent(previewUrl: string) {
    const [content, setContent] = useState("");
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    useEffect(() => {
        const controller = new AbortController();
        let active = true;

        async function loadText() {
            setLoading(true);
            setError("");
            try {
                const response = await fetch(previewUrl, {
                    credentials: "include",
                    signal: controller.signal,
                });
                if (!response.ok) {
                    throw new Error(`加载文本失败（${response.status}）`);
                }
                const text = await response.text();
                if (!active) return;
                setContent(text);
            } catch (err) {
                if (!active) return;
                const abortError =
                    err instanceof DOMException && err.name === "AbortError";
                if (abortError) return;
                setError(err instanceof Error ? err.message : "加载文本失败。");
                setContent("");
            } finally {
                if (active) {
                    setLoading(false);
                }
            }
        }

        void loadText();
        return () => {
            active = false;
            controller.abort();
        };
    }, [previewUrl]);

    return { content, loading, error };
}
