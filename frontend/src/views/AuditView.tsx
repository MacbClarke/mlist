import { useCallback, useEffect, useRef, useState } from "react";
import {
    ActivityIcon,
    AlertCircleIcon,
    CheckCircleIcon,
    CircleOffIcon,
    DownloadIcon,
    RefreshCwIcon,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
} from "@/components/ui/card";
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table";
import { FormError } from "@/components/FormError";
import { formatBytes, formatDate, formatRange } from "@/lib/format";
import { apiJson } from "@/api";
import {
    AUDIT_PAGE_SIZE,
    type AuditEventsResponse,
    type AuditResourcesResponse,
    type ResourceAccessEvent,
    type ResourceUsage,
    type UserView,
} from "@/types";

export function AuditView({
    users,
    selectedUserId,
    onUserChange,
}: {
    users: UserView[];
    selectedUserId: string;
    onUserChange: (value: string) => void;
}) {
    const [events, setEvents] = useState<ResourceAccessEvent[]>([]);
    const [resources, setResources] = useState<ResourceUsage[]>([]);
    const [eventsPage, setEventsPage] = useState(0);
    const [resourcesPage, setResourcesPage] = useState(0);
    const [eventsHasMore, setEventsHasMore] = useState(false);
    const [resourcesHasMore, setResourcesHasMore] = useState(false);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");
    const auditRequestRef = useRef(0);
    const auditInFlightRef = useRef(0);

    const loadAudit = useCallback(
        async (showLoading = true, skipIfBusy = false) => {
            if (skipIfBusy && auditInFlightRef.current > 0) return;
            auditInFlightRef.current += 1;
            const requestId = auditRequestRef.current + 1;
            auditRequestRef.current = requestId;
            if (showLoading) {
                setLoading(true);
            }
            setError("");
            try {
                const baseQuery = new URLSearchParams({
                    limit: String(AUDIT_PAGE_SIZE),
                });
                if (selectedUserId !== "all") {
                    baseQuery.set("userId", selectedUserId);
                }
                const eventsQuery = new URLSearchParams(baseQuery);
                eventsQuery.set("offset", String(eventsPage * AUDIT_PAGE_SIZE));
                const resourcesQuery = new URLSearchParams(baseQuery);
                resourcesQuery.set(
                    "offset",
                    String(resourcesPage * AUDIT_PAGE_SIZE),
                );
                const [eventsPayload, resourcesPayload] = await Promise.all([
                    apiJson<AuditEventsResponse>(
                        `/api/admin/audit/events?${eventsQuery}`,
                    ),
                    apiJson<AuditResourcesResponse>(
                        `/api/admin/audit/resources?${resourcesQuery}`,
                    ),
                ]);
                if (auditRequestRef.current !== requestId) return;
                setEvents(eventsPayload.events);
                setResources(resourcesPayload.resources);
                setEventsHasMore(eventsPayload.hasMore);
                setResourcesHasMore(resourcesPayload.hasMore);
            } catch (err) {
                if (auditRequestRef.current === requestId) {
                    setError(
                        err instanceof Error ? err.message : "审计数据加载失败",
                    );
                }
            } finally {
                if (showLoading && auditRequestRef.current === requestId) {
                    setLoading(false);
                }
                auditInFlightRef.current = Math.max(
                    0,
                    auditInFlightRef.current - 1,
                );
            }
        },
        [eventsPage, resourcesPage, selectedUserId],
    );

    useEffect(() => {
        let cancelled = false;
        let timer: number | undefined;

        async function loadAndSchedule(showLoading: boolean) {
            await loadAudit(showLoading, !showLoading);
            if (cancelled) return;
            timer = window.setTimeout(() => void loadAndSchedule(false), 5000);
        }

        void loadAndSchedule(true);
        return () => {
            cancelled = true;
            if (timer !== undefined) {
                window.clearTimeout(timer);
            }
        };
    }, [loadAudit]);

    function handleUserChange(value: string) {
        setEventsPage(0);
        setResourcesPage(0);
        onUserChange(value);
    }

    return (
        <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
                <Select value={selectedUserId} onValueChange={handleUserChange}>
                    <SelectTrigger className="w-full sm:w-56">
                        <SelectValue placeholder="选择用户" />
                    </SelectTrigger>
                    <SelectContent>
                        <SelectItem value="all">全部用户</SelectItem>
                        {users.map((user) => (
                            <SelectItem key={user.id} value={String(user.id)}>
                                {user.username}
                            </SelectItem>
                        ))}
                    </SelectContent>
                </Select>
                <Button
                    variant="outline"
                    onClick={() => void loadAudit()}
                    disabled={loading}
                >
                    <RefreshCwIcon
                        className={`size-4 ${loading ? "animate-spin" : ""}`}
                    />
                    刷新
                </Button>
            </div>
            {error ? <FormError title="审计加载失败" message={error} /> : null}
            <Card>
                <CardHeader className="gap-3">
                    <div className="flex flex-wrap items-center gap-2">
                        <CardTitle className="flex flex-1 items-center gap-2 text-base">
                            <DownloadIcon className="size-4" />
                            文件流量
                        </CardTitle>
                        <AuditPager
                            page={resourcesPage}
                            hasMore={resourcesHasMore}
                            disabled={loading}
                            onPageChange={setResourcesPage}
                        />
                    </div>
                    <CardDescription>
                        按服务端实际流式发送的字节数累计。
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    {loading && resources.length === 0 ? (
                        <p className="text-muted-foreground py-6 text-center text-sm">
                            正在加载文件流量...
                        </p>
                    ) : resources.length === 0 ? (
                        <p className="text-muted-foreground rounded-md border border-dashed px-3 py-4 text-center text-sm">
                            暂无文件访问记录
                        </p>
                    ) : (
                        <ul className="space-y-2">
                            {resources.map((resource) => (
                                <ResourceUsageRow
                                    key={`${resource.userId}:${resource.path}`}
                                    resource={resource}
                                    showUser={selectedUserId === "all"}
                                />
                            ))}
                        </ul>
                    )}
                </CardContent>
            </Card>
            <Card className="py-1">
                <CardHeader className="gap-3 px-4 py-3">
                    <div className="flex flex-wrap items-center gap-2">
                        <CardTitle className="flex-1 text-base">
                            最近访问
                        </CardTitle>
                        <AuditPager
                            page={eventsPage}
                            hasMore={eventsHasMore}
                            disabled={loading}
                            onPageChange={setEventsPage}
                        />
                    </div>
                    <CardDescription>
                        最近 90 天内的目录、文件和进行中拉流。
                    </CardDescription>
                </CardHeader>
                <CardContent className="p-0">
                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead>更新时间</TableHead>
                                <TableHead>用户</TableHead>
                                <TableHead>类型</TableHead>
                                <TableHead>状态</TableHead>
                                <TableHead>路径</TableHead>
                                <TableHead className="hidden md:table-cell">
                                    Range
                                </TableHead>
                                <TableHead className="text-right">
                                    流量
                                </TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {loading && events.length === 0 ? (
                                <TableRow>
                                    <TableCell
                                        colSpan={7}
                                        className="text-muted-foreground py-6 text-center"
                                    >
                                        正在加载访问记录...
                                    </TableCell>
                                </TableRow>
                            ) : events.length === 0 ? (
                                <TableRow>
                                    <TableCell
                                        colSpan={7}
                                        className="text-muted-foreground py-6 text-center"
                                    >
                                        暂无访问记录
                                    </TableCell>
                                </TableRow>
                            ) : (
                                events.map((event) => (
                                    <TableRow key={event.id}>
                                        <TableCell className="text-muted-foreground whitespace-nowrap">
                                            {formatDate(event.updatedAt)}
                                        </TableCell>
                                        <TableCell>{event.username}</TableCell>
                                        <TableCell>
                                            <Badge variant="outline">
                                                {event.resourceKind === "file"
                                                    ? "文件"
                                                    : "目录"}
                                            </Badge>
                                        </TableCell>
                                        <TableCell>
                                            <TransferStateBadge event={event} />
                                        </TableCell>
                                        <TableCell className="max-w-[22rem] truncate font-mono text-xs">
                                            {event.path || "/"}
                                        </TableCell>
                                        <TableCell className="text-muted-foreground hidden font-mono text-xs md:table-cell">
                                            {formatRange(
                                                event.rangeStart,
                                                event.rangeEnd,
                                            )}
                                        </TableCell>
                                        <TableCell className="text-right text-muted-foreground">
                                            {formatBytes(event.bytesServed)}
                                        </TableCell>
                                    </TableRow>
                                ))
                            )}
                        </TableBody>
                    </Table>
                </CardContent>
            </Card>
        </div>
    );
}

function TransferStateBadge({ event }: { event: ResourceAccessEvent }) {
    const endedAt = event.endedAt
        ? `结束：${formatDate(event.endedAt)}`
        : "尚未结束";
    if (event.transferState === "active") {
        return (
            <Badge
                variant="outline"
                className="border-sky-300 bg-sky-50 text-sky-700 dark:border-sky-800 dark:bg-sky-950 dark:text-sky-300"
                title={endedAt}
            >
                <ActivityIcon className="size-3" />
                进行中
            </Badge>
        );
    }
    if (event.transferState === "aborted") {
        return (
            <Badge
                variant="outline"
                className="border-amber-300 bg-amber-50 text-amber-700 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-300"
                title={endedAt}
            >
                <CircleOffIcon className="size-3" />
                已中断
            </Badge>
        );
    }
    if (event.transferState === "failed") {
        return (
            <Badge variant="destructive" title={endedAt}>
                <AlertCircleIcon className="size-3" />
                失败
            </Badge>
        );
    }
    if (event.transferState === "stale") {
        return (
            <Badge variant="secondary" title={endedAt}>
                <CircleOffIcon className="size-3" />
                失联
            </Badge>
        );
    }
    return (
        <Badge variant="secondary" title={endedAt}>
            <CheckCircleIcon className="size-3" />
            完成
        </Badge>
    );
}

function ResourceUsageRow({
    resource,
    showUser,
}: {
    resource: ResourceUsage;
    showUser: boolean;
}) {
    return (
        <li
            className="overflow-hidden rounded-md border px-3 py-2"
            title={`${resource.path} · ${formatBytes(resource.totalBytesServed)}`}
        >
            <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
                <span className="min-w-0 flex-1 truncate font-mono text-xs">
                    {resource.path}
                </span>
                <span className="text-sm font-medium">
                    {formatBytes(resource.totalBytesServed)}
                </span>
            </div>
            <div className="text-muted-foreground mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs">
                {showUser ? <span>{resource.username}</span> : null}
                <span>{resource.accessCount} 次访问</span>
                <span>{formatDate(resource.lastAccessAt)}</span>
            </div>
        </li>
    );
}

function AuditPager({
    page,
    hasMore,
    disabled,
    onPageChange,
}: {
    page: number;
    hasMore: boolean;
    disabled: boolean;
    onPageChange: (page: number) => void;
}) {
    return (
        <div className="flex items-center gap-2">
            <Button
                variant="outline"
                size="xs"
                onClick={() => onPageChange(Math.max(0, page - 1))}
                disabled={disabled || page === 0}
            >
                上一页
            </Button>
            <span className="text-muted-foreground min-w-12 text-center text-xs">
                第 {page + 1} 页
            </span>
            <Button
                variant="outline"
                size="xs"
                onClick={() => onPageChange(page + 1)}
                disabled={disabled || !hasMore}
            >
                下一页
            </Button>
        </div>
    );
}
