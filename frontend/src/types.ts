export type EntryKind = "dir" | "file";

export type ListEntry = {
    name: string;
    path: string;
    kind: EntryKind;
    size?: number;
    mtime?: number;
    mime?: string;
    requiresAuth: boolean;
    authorized: boolean;
    favorite: boolean;
};

export type ListResponse = {
    path: string;
    entries: ListEntry[];
    requiresAuth: boolean;
    authorized: boolean;
    total: number;
    hasMore: boolean;
};

export type FavoritePath = { path: string; createdAt: number };

export type FavoritesResponse = {
    paths: FavoritePath[];
};

export type SortOrder = "asc" | "desc";
export type SortField = "" | "name" | "size" | "mtime";

export type UserRole = "admin" | "user";

export type UserView = {
    id: number;
    username: string;
    role: UserRole;
    enabled: boolean;
    createdAt: number;
    updatedAt: number;
    lastLoginAt?: number | null;
    lastSeenAt?: number | null;
    totalBytesServed: number;
};

export type MeResponse = {
    authenticated: boolean;
    user: UserView | null;
    accessExpiresAt: string | null;
    needsBootstrap: boolean;
};

export type LoginResponse = {
    ok: boolean;
    user: UserView;
    accessToken: string;
    accessExpiresAt: string;
    refreshExpiresAt: string;
};

export type RefreshResponse = {
    ok: boolean;
    user: UserView;
    accessToken: string;
    accessExpiresAt: string;
    refreshExpiresAt: string;
};

export type TotpBinding = {
    user: UserView;
    secret: string;
    otpauthUrl: string;
    qrDataUrl: string;
};

export type BootstrapStartResponse = {
    username: string;
    secret: string;
    otpauthUrl: string;
    qrDataUrl: string;
};

export type UsersResponse = {
    users: UserView[];
};

export type TransferState = "active" | "completed" | "aborted" | "failed" | "stale";

export type ResourceAccessEvent = {
    id: number;
    userId: number;
    username: string;
    resourceKind: "directory" | "file";
    path: string;
    route: string;
    status: number;
    bytesServed: number;
    fileSize?: number | null;
    rangeStart?: number | null;
    rangeEnd?: number | null;
    transferState: TransferState;
    createdAt: number;
    updatedAt: number;
    endedAt?: number | null;
};

export type ResourceUsage = {
    userId: number;
    username: string;
    path: string;
    fileSize?: number | null;
    accessCount: number;
    totalBytesServed: number;
    lastAccessAt: number;
};

export type AuditEventsResponse = {
    events: ResourceAccessEvent[];
    hasMore: boolean;
};

export type AuditResourcesResponse = {
    resources: ResourceUsage[];
    hasMore: boolean;
};

export type FileState = {
    path: string;
    highlighted: boolean;
    updatedAt: number;
};

export type FileStatesResponse = {
    files: FileState[];
};

export type SignedFileLinkResponse = {
    url: string;
    expiresAt: string;
};

export type ApiError = {
    code?: string;
    message?: string;
};

export type LoadPathOptions = {
    updateUrl?: boolean;
    replaceUrl?: boolean;
    previewPath?: string | null;
    allowPathAsFile?: boolean;
    resetOffset?: boolean;
    sortOverride?: SortField;
    orderOverride?: SortOrder;
    offsetOverride?: number;
    viewOverride?: "all" | "favorites";
    searchOverride?: string;
};

export const AUDIT_PAGE_SIZE = 50;
export const TOTP_CODE_LENGTH = 6;
