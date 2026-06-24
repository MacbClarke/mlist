import { Fragment, useMemo } from "react";
import {
    CircleOffIcon,
    CopyIcon,
    DownloadIcon,
    EyeIcon,
    LockIcon,
    StarIcon,
} from "lucide-react";
import {
    flexRender,
    getCoreRowModel,
    useReactTable,
} from "@tanstack/react-table";
import type { ColumnDef } from "@tanstack/react-table";

import {
    ContextMenu,
    ContextMenuContent,
    ContextMenuItem,
    ContextMenuTrigger,
} from "@/components/ui/context-menu";
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table";
import { EntryIcon } from "@/components/EntryIcon";
import { formatBytes, formatDate } from "@/lib/format";
import type { ListEntry, SortField, SortOrder } from "@/types";

export function EntriesTable({
    entries,
    sorting,
    onSort,
    onOpen,
    onToggleFavorite,
    isFileHighlighted,
    onDownload,
    onCopy,
    onUnmarkHighlight,
}: {
    entries: ListEntry[];
    sorting: { sort: SortField; order: SortOrder };
    onSort: (field: SortField) => void;
    onOpen: (entry: ListEntry) => void;
    onToggleFavorite: (entry: ListEntry) => void;
    isFileHighlighted: (path: string) => boolean;
    onDownload: (entry: ListEntry) => void;
    onCopy: (entry: ListEntry) => void;
    onUnmarkHighlight: (entry: ListEntry) => void;
}) {
    const columns = useMemo<ColumnDef<ListEntry>[]>(
        () => [
            {
                id: "name",
                header: () => (
                    <SortHeader
                        label="名称"
                        field="name"
                        sorting={sorting}
                        onSort={onSort}
                        align="left"
                    />
                ),
                cell: ({ row }) => (
                    <NameCell entry={row.original} onOpen={onOpen} />
                ),
            },
            {
                id: "size",
                header: () => (
                    <SortHeader
                        label="大小"
                        field="size"
                        sorting={sorting}
                        onSort={onSort}
                        align="right"
                    />
                ),
                cell: ({ row }) => (
                    <span className="text-muted-foreground text-xs text-right">
                        {row.original.kind === "file"
                            ? formatBytes(row.original.size ?? 0)
                            : "--"}
                    </span>
                ),
            },
            {
                id: "mtime",
                header: () => (
                    <SortHeader
                        label="修改时间"
                        field="mtime"
                        sorting={sorting}
                        onSort={onSort}
                        align="right"
                    />
                ),
                cell: ({ row }) => (
                    <span className="text-muted-foreground text-xs text-right">
                        {row.original.mtime
                            ? formatDate(row.original.mtime)
                            : "--"}
                    </span>
                ),
            },
        ],
        [sorting, onSort, onOpen],
    );

    // eslint-disable-next-line react-hooks/incompatible-library
    const table = useReactTable({
        data: entries,
        columns,
        getCoreRowModel: getCoreRowModel(),
        manualSorting: true,
    });

    return (
        <Table>
            <TableHeader>
                {table.getHeaderGroups().map((headerGroup) => (
                    <TableRow key={headerGroup.id}>
                        <TableHead
                            colSpan={columns.length}
                            className="h-9 p-0"
                        >
                            <div className="grid w-full grid-cols-[1fr_auto_auto] items-center gap-3 px-3 sm:grid-cols-[1fr_7rem_9rem]">
                                {headerGroup.headers.map((header) => (
                                    <Fragment key={header.id}>
                                        {flexRender(
                                            header.column.columnDef.header,
                                            header.getContext(),
                                        )}
                                    </Fragment>
                                ))}
                            </div>
                        </TableHead>
                    </TableRow>
                ))}
            </TableHeader>
            <TableBody>
                {table.getRowModel().rows.map((row) => {
                    const entry = row.original;
                    const highlighted =
                        entry.kind === "file" && isFileHighlighted(entry.path);
                    return (
                        <TableRow
                            key={entry.path}
                            className={`h-auto ${highlighted ? "bg-emerald-100/70 hover:bg-emerald-100" : "hover:bg-muted/50"}`}
                        >
                            <TableCell colSpan={columns.length} className="p-0">
                                <ContextMenu>
                                    <ContextMenuTrigger asChild>
                                        <button
                                            type="button"
                                            onClick={() => onOpen(entry)}
                                            className="grid w-full grid-cols-[1fr_auto_auto] items-center gap-3 px-3 py-2.5 text-left sm:grid-cols-[1fr_7rem_9rem]"
                                        >
                                            {row
                                                .getVisibleCells()
                                                .map((cell) => (
                                                    <Fragment key={cell.id}>
                                                        {flexRender(
                                                            cell.column
                                                                .columnDef.cell,
                                                            cell.getContext(),
                                                        )}
                                                    </Fragment>
                                                ))}
                                        </button>
                                    </ContextMenuTrigger>
                                    <ContextMenuContent className="w-44">
                                        {entry.kind === "file" ? (
                                            <ContextMenuItem
                                                onSelect={() => onOpen(entry)}
                                            >
                                                <EyeIcon className="mr-2 size-4" />
                                                预览
                                            </ContextMenuItem>
                                        ) : null}
                                        {entry.kind === "file" ? (
                                            <>
                                                <ContextMenuItem
                                                    onSelect={() =>
                                                        onDownload(entry)
                                                    }
                                                >
                                                    <DownloadIcon className="mr-2 size-4" />
                                                    下载
                                                </ContextMenuItem>
                                                <ContextMenuItem
                                                    onSelect={() =>
                                                        onCopy(entry)
                                                    }
                                                >
                                                    <CopyIcon className="mr-2 size-4" />
                                                    复制链接
                                                </ContextMenuItem>
                                            </>
                                        ) : null}
                                        <ContextMenuItem
                                            onSelect={() =>
                                                onToggleFavorite(entry)
                                            }
                                        >
                                            <StarIcon className="mr-2 size-4" />
                                            {entry.favorite
                                                ? "取消收藏"
                                                : "收藏"}
                                        </ContextMenuItem>
                                        {highlighted ? (
                                            <ContextMenuItem
                                                onSelect={() =>
                                                    onUnmarkHighlight(entry)
                                                }
                                            >
                                                <CircleOffIcon className="mr-2 size-4" />
                                                取消高亮
                                            </ContextMenuItem>
                                        ) : null}
                                    </ContextMenuContent>
                                </ContextMenu>
                            </TableCell>
                        </TableRow>
                    );
                })}
            </TableBody>
        </Table>
    );
}

function SortHeader({
    label,
    field,
    sorting,
    onSort,
    align,
}: {
    label: string;
    field: SortField;
    sorting: { sort: SortField; order: SortOrder };
    onSort: (field: SortField) => void;
    align: "left" | "right";
}) {
    const active = sorting.sort === field;
    return (
        <button
            type="button"
            onClick={() => onSort(field)}
            className={`text-muted-foreground flex items-center gap-1 text-xs hover:text-foreground ${
                align === "right" ? "ml-auto w-full justify-end" : ""
            }`}
        >
            {label}
            {active ? (sorting.order === "asc" ? " ↑" : " ↓") : null}
        </button>
    );
}

function NameCell({
    entry,
    onOpen,
}: {
    entry: ListEntry;
    onOpen: (entry: ListEntry) => void;
}) {
    return (
        <button
            type="button"
            onClick={() => onOpen(entry)}
            className="flex min-w-0 items-center gap-2 text-left"
        >
            <EntryIcon entry={entry} />
            <span className="min-w-0 truncate">{entry.name}</span>
            {entry.favorite ? (
                <StarIcon
                    className="size-3.5 shrink-0 fill-yellow-400 text-yellow-400"
                    aria-label="已收藏"
                />
            ) : null}
            {entry.requiresAuth && !entry.authorized ? (
                <span
                    className="inline-flex shrink-0"
                    aria-label="私有目录"
                    title="私有目录"
                >
                    <LockIcon
                        className="text-muted-foreground size-3.5"
                        aria-hidden
                    />
                </span>
            ) : null}
        </button>
    );
}
