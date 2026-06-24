import type {
    ApiError,
    MeResponse,
    RefreshResponse,
    SignedFileLinkResponse,
} from "@/types";

let accessToken: string | null = null;
let refreshPromise: Promise<RefreshResponse> | null = null;

export function setAccessToken(token: string | null) {
    accessToken = token;
}

export class ApiRequestError extends Error {
    status: number;
    code?: string;

    constructor(status: number, message: string, code?: string) {
        super(message);
        this.name = "ApiRequestError";
        this.status = status;
        this.code = code;
    }
}

export async function refreshAccessToken(): Promise<RefreshResponse> {
    if (!refreshPromise) {
        refreshPromise = apiJson<RefreshResponse>(
            "/api/auth/refresh",
            { method: "POST" },
            { skipRefresh: true },
        )
            .then((payload) => {
                setAccessToken(payload.accessToken);
                return payload;
            })
            .finally(() => {
                refreshPromise = null;
            });
    }
    return refreshPromise;
}

export async function apiJson<T>(
    url: string,
    init: RequestInit = {},
    options: { skipRefresh?: boolean } = {},
): Promise<T> {
    return apiJsonRequest<T>(url, init, options);
}

async function apiJsonRequest<T>(
    url: string,
    init: RequestInit,
    options: { skipRefresh?: boolean },
): Promise<T> {
    const headers = new Headers(init.headers);
    if (init.body && !headers.has("Content-Type")) {
        headers.set("Content-Type", "application/json");
    }
    if (accessToken && !headers.has("Authorization")) {
        headers.set("Authorization", `Bearer ${accessToken}`);
    }

    const response = await fetch(url, {
        ...init,
        headers,
        credentials: "include",
    });

    if (!response.ok) {
        const payload = (await response.json().catch(() => ({}))) as ApiError;
        const error = new ApiRequestError(
            response.status,
            payload.message ?? `请求失败（${response.status}）`,
            payload.code,
        );
        if (
            !options.skipRefresh &&
            response.status === 401 &&
            payload.code === "AUTH_REQUIRED"
        ) {
            try {
                await refreshAccessToken();
                return apiJsonRequest<T>(url, init, { skipRefresh: true });
            } catch {
                setAccessToken(null);
            }
        }
        throw error;
    }

    return (await response.json()) as T;
}

export async function fetchMe(): Promise<MeResponse> {
    return apiJson<MeResponse>("/api/me");
}

export async function createSignedFileLink(
    path: string,
): Promise<SignedFileLinkResponse> {
    return apiJson<SignedFileLinkResponse>("/api/file-link", {
        method: "POST",
        body: JSON.stringify({ path }),
    });
}
