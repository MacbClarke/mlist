import { useQuery } from "@tanstack/react-query";
import { queryKeys } from "@/lib/queryClient";

export function useRemoteTextContent(previewUrl: string) {
    const { data, isLoading, error } = useQuery({
        queryKey: queryKeys.previewText(previewUrl),
        queryFn: async ({ signal }) => {
            const response = await fetch(previewUrl, {
                credentials: "include",
                signal,
            });
            if (!response.ok) {
                throw new Error(`加载文本失败（${response.status}）`);
            }
            return response.text();
        },
        enabled: Boolean(previewUrl),
        staleTime: 5 * 60 * 1000,
    });

    return {
        content: data ?? "",
        loading: isLoading,
        error: error instanceof Error ? error.message : "",
    };
}
