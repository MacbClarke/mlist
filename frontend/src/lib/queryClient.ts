import { QueryClient } from "@tanstack/react-query";
import { ApiRequestError } from "@/api";

export const queryClient = new QueryClient({
    defaultOptions: {
        queries: {
            staleTime: 30 * 1000,
            gcTime: 5 * 60 * 1000,
            refetchOnWindowFocus: false,
            retry: (failureCount, error) => {
                if (
                    error instanceof ApiRequestError &&
                    (error.status === 400 ||
                        error.status === 401 ||
                        error.status === 403 ||
                        error.status === 404)
                ) {
                    return false;
                }
                return failureCount < 2;
            },
        },
    },
});

export const queryKeys = {
    me: () => ["auth", "me"] as const,
    fileStates: () => ["file-states"] as const,
    favorites: () => ["favorites"] as const,
    list: (params: {
        path: string;
        sort?: string;
        order?: string;
        offset?: number;
        limit?: number;
        favoritesOnly?: boolean;
        search?: string;
    }) => ["list", params] as const,
    signedLink: (path: string) => ["file-link", path] as const,
    previewText: (url: string) => ["preview-text", url] as const,
    adminUsers: () => ["admin", "users"] as const,
    adminAuditEvents: (params: {
        userId?: string;
        offset: number;
        limit: number;
    }) => ["admin", "audit", "events", params] as const,
    adminAuditResources: (params: {
        userId?: string;
        offset: number;
        limit: number;
    }) => ["admin", "audit", "resources", params] as const,
};
