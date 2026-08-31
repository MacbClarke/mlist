import { useEffect, useMemo, useRef, useState } from "react";
import {
    AlertCircleIcon,
    ArrowLeftIcon,
    CopyIcon,
    DownloadIcon,
    RefreshCwIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { EntriesTable } from "@/components/EntriesTable";
import { FilePreview } from "@/components/FilePreview";
import { PathBreadcrumbs } from "@/components/PathBreadcrumbs";
import { Shell, TopBar } from "@/components/TopBar";
import { AdminView } from "@/views/AdminView";
import { BootstrapView } from "@/views/BootstrapView";
import { LoginView } from "@/views/LoginView";
import {
    ApiRequestError,
    apiJson,
    createSignedBatchLink,
    createSignedFileLink,
    fetchMe,
    refreshAccessToken,
    setAccessToken,
} from "@/api";
import { queryClient, queryKeys } from "@/lib/queryClient";
import {
    browserPath,
    isAdminPath,
    normalizeOptionalPath,
    normalizePath,
    parentPathOf,
    pathFromLocation,
    syncBrowserState,
    toAbsoluteUrl,
} from "@/lib/path";
import type {
    FavoritePath,
    FavoritesResponse,
    FileState,
    FileStatesResponse,
    ListEntry,
    ListResponse,
    LoadPathOptions,
    LoginResponse,
    MeResponse,
    SortField,
    SortOrder,
    UserView,
} from "@/types";

function App() {
    const [authLoading, setAuthLoading] = useState(true);
    const [user, setUser] = useState<UserView | null>(null);
    const [needsBootstrap, setNeedsBootstrap] = useState(false);
    const [adminRoute, setAdminRoute] = useState(() =>
        isAdminPath(window.location.pathname),
    );
    const [currentPath, setCurrentPath] = useState("");
    const [entries, setEntries] = useState<ListEntry[]>([]);
    const [previewEntry, setPreviewEntry] = useState<ListEntry | null>(null);
    const [loading, setLoading] = useState(false);
    const [refreshing, setRefreshing] = useState(false);
    const [error, setError] = useState("");
    const [pathNotFound, setPathNotFound] = useState(false);
    const [highlightedFiles, setHighlightedFiles] = useState<Set<string>>(
        () => new Set(),
    );
    const [favoriteFiles, setFavoriteFiles] = useState<Set<string>>(
        () => new Set(),
    );
    const [selectedPaths, setSelectedPaths] = useState<Set<string>>(
        () => new Set(),
    );
    const [view, setView] = useState<"all" | "favorites">("all");
    const [sorting, setSorting] = useState<{
        sort: SortField;
        order: SortOrder;
    }>({
        sort: "",
        order: "asc",
    });
    const [pagination, setPagination] = useState({ offset: 0, limit: 50 });
    const [search, setSearch] = useState("");
    const searchDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
    const [total, setTotal] = useState(0);
    const [hasMore, setHasMore] = useState(false);

    const crumbs = useMemo(() => {
        if (!currentPath) return [{ label: "/", path: "" }];
        const parts = currentPath.split("/");
        return [
            { label: "/", path: "" },
            ...parts.map((part, index) => ({
                label: part,
                path: parts.slice(0, index + 1).join("/"),
            })),
        ];
    }, [currentPath]);

    useEffect(() => {
        void bootstrapApp();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    useEffect(() => {
        return () => {
            if (searchDebounceRef.current) {
                window.clearTimeout(searchDebounceRef.current);
                searchDebounceRef.current = null;
            }
        };
    }, []);

    useEffect(() => {
        const handlePopState = () => {
            const nextIsAdmin = isAdminPath(window.location.pathname);
            setAdminRoute(nextIsAdmin);
            setPreviewEntry(null);
            if (!nextIsAdmin && user) {
                const nextPath = pathFromLocation(window.location.pathname);
                void loadPath(nextPath, {
                    updateUrl: false,
                    resetOffset: true,
                });
            }
        };

        window.addEventListener("popstate", handlePopState);
        return () => window.removeEventListener("popstate", handlePopState);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [user]);

    async function bootstrapApp() {
        setAuthLoading(true);
        try {
            const refreshed = await refreshAccessToken().catch(() => null);
            if (refreshed) {
                setAccessToken(refreshed.accessToken);
            }
            const me = await fetchMe();
            applyMe(me);
            if (me.authenticated && me.user) {
                await loadHighlightedFilesFromServer();
                await loadFavoriteFilesFromServer();
                if (isAdminPath(window.location.pathname)) {
                    setAdminRoute(true);
                } else {
                    await loadPath(pathFromLocation(window.location.pathname), {
                        replaceUrl: true,
                        resetOffset: true,
                    });
                }
            }
        } catch (err) {
            setError(err instanceof Error ? err.message : "认证状态加载失败");
        } finally {
            setAuthLoading(false);
        }
    }

    function applyMe(me: MeResponse) {
        setUser(me.user);
        setNeedsBootstrap(me.needsBootstrap);
    }

    function clearSearchDebounce() {
        if (searchDebounceRef.current) {
            window.clearTimeout(searchDebounceRef.current);
            searchDebounceRef.current = null;
        }
    }

    function applyListPayload(
        payload: ListResponse,
        requestedPreviewPath: string | null | undefined,
        options: LoadPathOptions,
    ) {
        const safeEntries = payload.entries.filter(
            (item) => item.name !== ".private",
        );
        let resolvedPreviewPath: string | null = null;
        if (requestedPreviewPath !== undefined) {
            const previewCandidate = requestedPreviewPath
                ? (safeEntries.find(
                      (item) =>
                          item.kind === "file" &&
                          normalizePath(item.path) === requestedPreviewPath,
                  ) ?? null)
                : null;
            setPreviewEntry(previewCandidate);
            resolvedPreviewPath = previewCandidate?.path ?? null;
        } else {
            setPreviewEntry(null);
        }

        setEntries(safeEntries);
        setTotal(payload.total ?? 0);
        setHasMore(payload.hasMore ?? false);
        setCurrentPath(payload.path);
        if (options.updateUrl !== false) {
            syncBrowserState(
                payload.path,
                resolvedPreviewPath,
                options.replaceUrl === true,
            );
        }
    }

    async function loadPath(path: string, options: LoadPathOptions = {}) {
        clearSearchDebounce();
        setSelectedPaths(new Set());
        const requestPath = normalizePath(path);
        const allowPathAsFile = options.allowPathAsFile !== false;
        const requestedPreviewPath =
            options.previewPath === undefined
                ? undefined
                : normalizeOptionalPath(options.previewPath);
        const effectiveOffset =
            options.offsetOverride ??
            (options.resetOffset ? 0 : pagination.offset);
        const effectiveView = options.viewOverride ?? view;
        const effectiveSearch = options.searchOverride ?? search;
        const effectiveSort =
            options.sortOverride !== undefined
                ? options.sortOverride
                : sorting.sort;
        const effectiveOrder =
            options.orderOverride !== undefined
                ? options.orderOverride
                : sorting.order;
        if (options.resetOffset && pagination.offset !== 0) {
            setPagination((previous) => ({ ...previous, offset: 0 }));
        }

        const queryKey = queryKeys.list({
            path: requestPath,
            sort: effectiveSort || undefined,
            order: effectiveOrder || undefined,
            offset: effectiveOffset,
            limit: pagination.limit,
            favoritesOnly: effectiveView === "favorites" ? true : undefined,
            search: effectiveSearch.trim() || undefined,
        });

        const cachedPayload = options.forceRefetch
            ? undefined
            : queryClient.getQueryData<ListResponse>(queryKey);
        if (cachedPayload) {
            applyListPayload(cachedPayload, requestedPreviewPath, options);
        } else if (!options.forceRefetch) {
            setLoading(true);
        }
        setError("");
        setPathNotFound(false);

        try {
            const params = new URLSearchParams({ path: requestPath });
            if (effectiveSort) {
                params.set("sort", effectiveSort);
                params.set("order", effectiveOrder);
            }
            params.set("offset", String(effectiveOffset));
            params.set("limit", String(pagination.limit));
            if (effectiveView === "favorites") {
                params.set("favoritesOnly", "true");
            }
            if (effectiveSearch.trim()) {
                params.set("search", effectiveSearch.trim());
            }

            const payload = await queryClient.fetchQuery({
                queryKey,
                queryFn: () =>
                    apiJson<ListResponse>(`/api/list?${params.toString()}`),
                staleTime: options.forceRefetch ? 0 : 30 * 1000,
            });
            applyListPayload(payload, requestedPreviewPath, options);
        } catch (err) {
            if (
                err instanceof ApiRequestError &&
                allowPathAsFile &&
                err.status === 400 &&
                err.code === "BAD_REQUEST" &&
                err.message.includes("not a directory") &&
                requestPath.length > 0
            ) {
                const parentPath = parentPathOf(requestPath);
                await loadPath(parentPath, {
                    updateUrl: options.updateUrl,
                    replaceUrl: options.replaceUrl,
                    previewPath: requestPath,
                    allowPathAsFile: false,
                });
                return;
            }
            if (err instanceof ApiRequestError && err.status === 404) {
                setPathNotFound(true);
                setError("");
            } else {
                setError(err instanceof Error ? err.message : "发生未知错误");
            }
            setEntries([]);
        } finally {
            setLoading(false);
        }
    }

    async function handleLogin(username: string, code: string) {
        const payload = await apiJson<LoginResponse>("/api/auth/login", {
            method: "POST",
            body: JSON.stringify({ username, code }),
        });
        setAccessToken(payload.accessToken);
        setUser(payload.user);
        setNeedsBootstrap(false);
        setAdminRoute(false);
        await loadHighlightedFilesFromServer();
        await loadFavoriteFilesFromServer();
        await loadPath("", { replaceUrl: true, resetOffset: true });
    }

    async function handleBootstrapFinish(
        username: string,
        secret: string,
        code: string,
    ) {
        const payload = await apiJson<LoginResponse>("/api/bootstrap/finish", {
            method: "POST",
            body: JSON.stringify({ username, secret, code }),
        });
        setAccessToken(payload.accessToken);
        setUser(payload.user);
        setNeedsBootstrap(false);
        setAdminRoute(false);
        await loadHighlightedFilesFromServer();
        await loadFavoriteFilesFromServer();
        await loadPath("", { replaceUrl: true, resetOffset: true });
    }

    async function logout() {
        await apiJson<{ ok: boolean }>("/api/auth/logout", { method: "POST" });
        setAccessToken(null);
        setUser(null);
        queryClient.clear();
        setEntries([]);
        setPreviewEntry(null);
        setCurrentPath("");
        setHighlightedFiles(new Set());
        setFavoriteFiles(new Set());
        setView("all");
        setSorting({ sort: "", order: "asc" });
        setPagination({ offset: 0, limit: 50 });
        setTotal(0);
        setHasMore(false);
        setAdminRoute(false);
        window.history.replaceState(null, "", "/");
    }

    async function loadHighlightedFilesFromServer() {
        const payload = await queryClient.fetchQuery({
            queryKey: queryKeys.fileStates(),
            queryFn: () => apiJson<FileStatesResponse>("/api/file-states"),
            staleTime: 0,
        });
        setHighlightedFiles(
            new Set(
                payload.files
                    .filter((item) => item.highlighted)
                    .map((item) => normalizePath(item.path))
                    .filter((path) => path.length > 0),
            ),
        );
    }

    function openAdmin() {
        setPreviewEntry(null);
        setAdminRoute(true);
        window.history.pushState(null, "", "/_mlist/admin");
    }

    function closeAdmin() {
        setAdminRoute(false);
        window.history.pushState(null, "", browserPath(currentPath));
        void loadPath(currentPath, { resetOffset: true });
    }

    function goHome() {
        setPreviewEntry(null);
        setPathNotFound(false);
        void loadPath("", { resetOffset: true });
    }

    function goParent() {
        if (!currentPath) return;
        const parts = currentPath.split("/");
        parts.pop();
        setPreviewEntry(null);
        void loadPath(parts.join("/"), { resetOffset: true });
    }

    function openEntry(entry: ListEntry) {
        if (entry.kind === "dir") {
            setPreviewEntry(null);
            void loadPath(entry.path, { resetOffset: true });
            return;
        }
        void markFileHighlighted(entry.path);
        setPreviewEntry(entry);
        syncBrowserState(currentPath, entry.path, false);
    }

    async function copyDownloadAddress(entry: ListEntry) {
        if (entry.kind === "dir") {
            const zipName = `${entry.name}.zip`;
            await copyBatchDownloadLink([entry.path], zipName);
            return;
        }
        const toastId = toast.loading("正在生成下载链接...");
        try {
            const payload = await createSignedFileLink(entry.path);
            toast.dismiss(toastId);
            const url = toAbsoluteUrl(payload.url);
            await navigator.clipboard.writeText(url);
            await markFileHighlighted(entry.path);
            toast.success("已复制下载链接");
        } catch {
            toast.dismiss(toastId);
            toast.error("复制失败，请检查浏览器剪贴板权限。");
        }
    }

    async function copyBatchDownloadLink(paths: string[], name?: string) {
        if (paths.length === 0) return;
        const toastId = toast.loading("正在生成下载链接...");
        try {
            const payload = await createSignedBatchLink(
                paths,
                currentPath || undefined,
                name,
            );
            toast.dismiss(toastId);
            const url = toAbsoluteUrl(payload.url);
            await navigator.clipboard.writeText(url);
            await loadHighlightedFilesFromServer();
            setSelectedPaths(new Set());
            toast.success("已复制下载链接");
        } catch (err) {
            toast.dismiss(toastId);
            toast.error(err instanceof Error ? err.message : "生成下载链接失败");
        }
    }

    async function downloadFile(entry: ListEntry) {
        const toastId = toast.loading("正在准备下载...");
        try {
            const payload = await createSignedFileLink(entry.path);
            toast.dismiss(toastId);
            void markFileHighlighted(entry.path);
            const anchor = document.createElement("a");
            anchor.href = payload.url;
            anchor.download = entry.name;
            anchor.rel = "noreferrer";
            document.body.appendChild(anchor);
            anchor.click();
            anchor.remove();
        } catch (err) {
            toast.dismiss(toastId);
            toast.error(err instanceof Error ? err.message : "准备下载失败");
        }
    }

    async function downloadEntry(entry: ListEntry) {
        if (entry.kind === "dir") {
            const zipName = `${entry.name}.zip`;
            await downloadBatch([entry.path], zipName);
            return;
        }
        await downloadFile(entry);
    }

    async function downloadBatch(paths: string[], name?: string) {
        if (paths.length === 0) return;
        const toastId = toast.loading("正在准备打包下载...");
        try {
            const payload = await createSignedBatchLink(
                paths,
                currentPath || undefined,
                name,
            );
            toast.dismiss(toastId);

            await loadHighlightedFilesFromServer();
            setSelectedPaths(new Set());

            const anchor = document.createElement("a");
            anchor.href = payload.url;
            anchor.download = name ?? "download.zip";
            anchor.rel = "noreferrer";
            document.body.appendChild(anchor);
            anchor.click();
            anchor.remove();

            toast.success("已开始下载 ZIP 包");
        } catch (err) {
            toast.dismiss(toastId);
            toast.error(err instanceof Error ? err.message : "打包下载失败");
        }
    }

    function toggleSelect(entry: ListEntry) {
        setSelectedPaths((previous) => {
            const next = new Set(previous);
            if (next.has(entry.path)) {
                next.delete(entry.path);
            } else {
                next.add(entry.path);
            }
            return next;
        });
    }

    function selectAll() {
        setSelectedPaths((previous) => {
            if (previous.size === entries.length) {
                return new Set();
            }
            return new Set(entries.map((item) => item.path));
        });
    }

    function isFileHighlighted(path: string): boolean {
        return highlightedFiles.has(normalizePath(path));
    }

    async function markFileHighlighted(path: string) {
        const normalizedPath = normalizePath(path);
        if (!normalizedPath) return;

        await setFileHighlighted(normalizedPath, true);
        setHighlightedFiles((previous) => {
            if (previous.has(normalizedPath)) return previous;
            const next = new Set(previous);
            next.add(normalizedPath);
            return next;
        });
    }

    async function unmarkFileHighlighted(path: string) {
        const normalizedPath = normalizePath(path);
        if (!normalizedPath) return;

        await setFileHighlighted(normalizedPath, false);
        setHighlightedFiles((previous) => {
            if (!previous.has(normalizedPath)) return previous;
            const next = new Set(previous);
            next.delete(normalizedPath);
            return next;
        });
    }

    async function setFileHighlighted(path: string, highlighted: boolean) {
        await apiJson<FileState>("/api/file-states", {
            method: "POST",
            body: JSON.stringify({ path, highlighted }),
        });
        void queryClient.invalidateQueries({
            queryKey: queryKeys.fileStates(),
        });
    }

    async function loadFavoriteFilesFromServer() {
        const payload = await queryClient.fetchQuery({
            queryKey: queryKeys.favorites(),
            queryFn: () => apiJson<FavoritesResponse>("/api/favorites"),
            staleTime: 60 * 1000,
        });
        setFavoriteFiles(
            new Set(
                payload.paths
                    .map((item) => normalizePath(item.path))
                    .filter((path) => path.length > 0),
            ),
        );
    }

    async function toggleFavorite(entry: ListEntry) {
        const normalizedPath = normalizePath(entry.path);
        if (!normalizedPath) return;
        const wasFavorite = favoriteFiles.has(normalizedPath);
        const nextFavorite = !wasFavorite;

        try {
            await apiJson<FavoritePath>("/api/favorites", {
                method: "POST",
                body: JSON.stringify({
                    path: normalizedPath,
                    favorite: nextFavorite,
                }),
            });
            void queryClient.invalidateQueries({
                queryKey: queryKeys.favorites(),
            });
            void queryClient.invalidateQueries({
                queryKey: ["list"],
            });
            setFavoriteFiles((previous) => {
                const next = new Set(previous);
                if (nextFavorite) next.add(normalizedPath);
                else next.delete(normalizedPath);
                return next;
            });
            setEntries((previous) =>
                previous.map((item) =>
                    normalizePath(item.path) === normalizedPath
                        ? { ...item, favorite: nextFavorite }
                        : item,
                ),
            );
            if (view === "favorites" && !nextFavorite) {
                void loadPath(currentPath, { updateUrl: false });
            }
        } catch {
            toast.error("更新收藏失败");
        }
    }

    function changeSort(field: SortField) {
        // 三态循环：升序 → 降序 → 取消排序
        let nextField: SortField = field;
        let nextOrder: SortOrder = "asc";
        if (sorting.sort === field) {
            if (sorting.order === "asc") {
                nextOrder = "desc";
            } else {
                nextField = "";
                nextOrder = "asc";
            }
        }
        setSorting({ sort: nextField, order: nextOrder });
        void loadPath(currentPath, {
            updateUrl: false,
            resetOffset: true,
            sortOverride: nextField,
            orderOverride: nextOrder,
        });
    }

    function changeView(next: "all" | "favorites") {
        if (next === view) return;
        setView(next);
        if (next === "favorites") {
            // 重新拉取收藏可在后端顺带清理失效行（改名/删除/私有化导致的死收藏），
            // 确保剪枝不要再被"幽灵收藏"撑出空目录。
            void loadFavoriteFilesFromServer().finally(() => {
                void loadPath(currentPath, {
                    updateUrl: false,
                    resetOffset: true,
                    viewOverride: next,
                });
            });
        } else {
            void loadPath(currentPath, {
                updateUrl: false,
                resetOffset: true,
                viewOverride: next,
            });
        }
    }

    function changeSearch(value: string) {
        setSearch(value);
        clearSearchDebounce();
        searchDebounceRef.current = window.setTimeout(() => {
            searchDebounceRef.current = null;
            void loadPath(currentPath, {
                updateUrl: false,
                resetOffset: true,
                searchOverride: value,
            });
        }, 1000);
    }

    function clearSearch() {
        if (!search) return;
        setSearch("");
        clearSearchDebounce();
        void loadPath(currentPath, {
            updateUrl: false,
            resetOffset: true,
            searchOverride: "",
        });
    }

    function goPrevPage() {
        if (pagination.offset === 0) return;
        const nextOffset = Math.max(0, pagination.offset - pagination.limit);
        setPagination((previous) => ({ ...previous, offset: nextOffset }));
        void loadPath(currentPath, {
            updateUrl: false,
            offsetOverride: nextOffset,
        });
    }

    function goNextPage() {
        if (!hasMore) return;
        const nextOffset = pagination.offset + pagination.limit;
        setPagination((previous) => ({ ...previous, offset: nextOffset }));
        void loadPath(currentPath, {
            updateUrl: false,
            offsetOverride: nextOffset,
        });
    }

    async function handleRefresh() {
        if (loading || refreshing) return;
        setRefreshing(true);
        const startTime = Date.now();
        try {
            await queryClient.resetQueries({
                queryKey: ["list"],
            });
            await Promise.all([
                loadPath(currentPath, {
                    forceRefetch: true,
                }),
                loadHighlightedFilesFromServer(),
                loadFavoriteFilesFromServer(),
            ]);
        } finally {
            const elapsed = Date.now() - startTime;
            const remaining = Math.max(0, 300 - elapsed);
            if (remaining > 0) {
                setTimeout(() => setRefreshing(false), remaining);
            } else {
                setRefreshing(false);
            }
        }
    }

    if (authLoading) {
        return (
            <Shell>
                <p className="text-muted-foreground px-3 py-4 text-sm">
                    正在加载...
                </p>
            </Shell>
        );
    }

    if (!user && needsBootstrap) {
        return (
            <Shell>
                <BootstrapView onFinish={handleBootstrapFinish} />
            </Shell>
        );
    }

    if (!user) {
        return (
            <Shell>
                <LoginView onLogin={handleLogin} />
            </Shell>
        );
    }

    if (adminRoute) {
        return (
            <Shell>
                <TopBar
                    user={user}
                    onAdmin={openAdmin}
                    onLogout={() => void logout()}
                    onBack={closeAdmin}
                    adminMode
                />
                <AdminView currentUser={user} onUserChanged={setUser} />
            </Shell>
        );
    }

    if (previewEntry) {
        return (
            <Shell>
                <TopBar
                    user={user}
                    onAdmin={openAdmin}
                    onLogout={() => void logout()}
                />
                <div className="mb-3 flex items-center gap-2">
                    <Button
                        variant="outline"
                        size="icon"
                        onClick={() => {
                            setPreviewEntry(null);
                            syncBrowserState(currentPath, null, false);
                        }}
                        aria-label="返回列表"
                        title="返回列表"
                    >
                        <ArrowLeftIcon className="size-4" />
                    </Button>

                    <div className="min-w-0 flex-1 overflow-x-auto">
                        <PathBreadcrumbs
                            crumbs={crumbs}
                            currentFile={previewEntry.name}
                            onNavigate={(path) => {
                                setPreviewEntry(null);
                                void loadPath(path);
                            }}
                        />
                    </div>

                    <Button
                        variant="outline"
                        size="icon"
                        onClick={() => void copyDownloadAddress(previewEntry)}
                        aria-label="复制链接"
                        title="复制链接"
                    >
                        <CopyIcon className="size-4" />
                    </Button>
                    <Button
                        variant="outline"
                        size="icon"
                        onClick={() => void downloadFile(previewEntry)}
                        aria-label="下载文件"
                        title="下载文件"
                    >
                        <DownloadIcon className="size-4" />
                    </Button>
                </div>

                {error ? (
                    <Alert variant="destructive" className="mb-3">
                        <AlertCircleIcon className="size-4" />
                        <AlertTitle>请求失败</AlertTitle>
                        <AlertDescription>{error}</AlertDescription>
                    </Alert>
                ) : null}

                <Card className="py-1">
                    <CardContent className="p-2">
                        <FilePreview entry={previewEntry} />
                    </CardContent>
                </Card>
            </Shell>
        );
    }

    return (
        <Shell>
            <TopBar
                user={user}
                onAdmin={openAdmin}
                onLogout={() => void logout()}
            />
            <div className="mb-3 flex items-center gap-2">
                <Button
                    variant="outline"
                    size="icon"
                    onClick={goParent}
                    disabled={!currentPath || loading}
                    aria-label="上一级"
                    title="上一级"
                >
                    <ArrowLeftIcon className="size-4" />
                </Button>

                <div className="min-w-0 flex-1 overflow-x-auto">
                    <PathBreadcrumbs
                        crumbs={crumbs}
                        onNavigate={(path) => {
                            setPreviewEntry(null);
                            void loadPath(path, { resetOffset: true });
                        }}
                    />
                </div>

                <Button
                    variant="outline"
                    size="icon"
                    onClick={() => void handleRefresh()}
                    disabled={loading || refreshing}
                    aria-label="刷新"
                    title="刷新"
                >
                    <RefreshCwIcon
                        className={`size-4 ${loading || refreshing ? "animate-spin" : ""}`}
                    />
                </Button>
            </div>

            <div className="mb-3 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex min-w-0 flex-1 flex-col gap-2 sm:flex-row sm:items-center">
                    <Tabs
                        value={view}
                        onValueChange={(value) =>
                            changeView(value as "all" | "favorites")
                        }
                    >
                        <TabsList>
                            <TabsTrigger value="all">全部</TabsTrigger>
                            <TabsTrigger value="favorites">收藏</TabsTrigger>
                        </TabsList>
                    </Tabs>
                    <div className="flex min-w-0 flex-1 items-center gap-2">
                        <Input
                            value={search}
                            onChange={(event) => changeSearch(event.target.value)}
                            placeholder="搜索当前目录的文件和文件夹"
                            className="h-9 max-w-sm bg-background shadow-sm"
                        />
                        {search ? (
                            <Button
                                variant="outline"
                                size="sm"
                                onClick={clearSearch}
                                disabled={loading}
                                className="shadow-sm"
                            >
                                清除
                            </Button>
                        ) : null}
                    </div>
                </div>
                {total > 0 ? (
                    <span className="text-muted-foreground shrink-0 text-xs">
                        共 {total} 项
                    </span>
                ) : null}
            </div>

            {pathNotFound ? (
                <Alert className="mb-3">
                    <AlertCircleIcon className="size-4" />
                    <AlertTitle>路径不存在</AlertTitle>
                    <AlertDescription className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                        <span>该目录或文件已不存在，可能已被删除、改名或无权访问。</span>
                        <Button variant="default" size="sm" onClick={goHome} disabled={loading}>
                            回到根目录
                        </Button>
                    </AlertDescription>
                </Alert>
            ) : error ? (
                <Alert variant="destructive" className="mb-3">
                    <AlertCircleIcon className="size-4" />
                    <AlertTitle>请求失败</AlertTitle>
                    <AlertDescription>{error}</AlertDescription>
                </Alert>
            ) : null}

            {!pathNotFound ? (
                <Card className="py-1">
                    <CardContent className="p-2">
                    {loading ? (
                        <p className="text-muted-foreground px-3 py-4 text-sm">
                            正在加载目录内容...
                        </p>
                    ) : entries.length === 0 ? (
                        <p className="text-muted-foreground rounded-md border border-dashed px-3 py-4 text-center text-sm">
                            {view === "favorites"
                                ? "还没有收藏的文件"
                                : "当前目录为空"}
                        </p>
                    ) : (
                        <EntriesTable
                            entries={entries}
                            sorting={sorting}
                            onSort={changeSort}
                            onOpen={openEntry}
                            onToggleFavorite={toggleFavorite}
                            isFileHighlighted={isFileHighlighted}
                            onDownload={(entry) => void downloadEntry(entry)}
                            onCopy={(entry) => void copyDownloadAddress(entry)}
                            onUnmarkHighlight={(entry) =>
                                void unmarkFileHighlighted(entry.path)
                            }
                            selectedPaths={selectedPaths}
                            onToggleSelect={toggleSelect}
                            onSelectAll={selectAll}
                        />
                    )}
                </CardContent>
            </Card>
            ) : null}

            {entries.length > 0 && (pagination.offset > 0 || hasMore) ? (
                <div className="mt-3 flex items-center justify-between">
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={goPrevPage}
                        disabled={pagination.offset === 0 || loading}
                    >
                        上一页
                    </Button>
                    <span className="text-muted-foreground text-xs">
                        {pagination.offset + 1} -{" "}
                        {Math.min(pagination.offset + entries.length, total)}
                        {" / "}
                        {total}
                    </span>
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={goNextPage}
                        disabled={!hasMore || loading}
                    >
                        下一页
                    </Button>
                </div>
            ) : null}

            {selectedPaths.size > 0 ? (
                <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-40 flex items-center gap-3 rounded-xl border bg-background/95 px-4 py-2.5 shadow-2xl backdrop-blur">
                    <span className="text-sm font-medium">
                        已选择 {selectedPaths.size} 项
                    </span>
                    <Button
                        size="sm"
                        onClick={() => {
                            const selectedList = Array.from(selectedPaths);
                            const defaultName = currentPath
                                ? `${currentPath.split("/").pop() || "files"}-selected.zip`
                                : "mlist-selected.zip";
                            void downloadBatch(selectedList, defaultName);
                        }}
                    >
                        <DownloadIcon className="mr-1.5 size-4" />
                        打包下载
                    </Button>
                    <Button
                        size="sm"
                        variant="outline"
                        onClick={() => {
                            const selectedList = Array.from(selectedPaths);
                            const defaultName = currentPath
                                ? `${currentPath.split("/").pop() || "files"}-selected.zip`
                                : "mlist-selected.zip";
                            void copyBatchDownloadLink(selectedList, defaultName);
                        }}
                    >
                        <CopyIcon className="mr-1.5 size-4" />
                        复制链接
                    </Button>
                    <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => setSelectedPaths(new Set())}
                    >
                        取消选择
                    </Button>
                </div>
            ) : null}
        </Shell>
    );
}

export default App;
