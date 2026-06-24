import type { ReactNode } from "react";
import {
    ArrowLeftIcon,
    DownloadIcon,
    LogOutIcon,
    SettingsIcon,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { formatBytes } from "@/lib/format";
import type { UserView } from "@/types";

export function Shell({ children }: { children: ReactNode }) {
    return <div className="mx-auto w-full max-w-6xl px-4 py-3">{children}</div>;
}

export function TopBar({
    user,
    adminMode = false,
    onAdmin,
    onLogout,
    onBack,
}: {
    user: UserView;
    adminMode?: boolean;
    onAdmin: () => void;
    onLogout: () => void;
    onBack?: () => void;
}) {
    return (
        <div className="mb-3 flex items-center gap-2 border-b pb-3">
            <div className="min-w-0 flex-1">
                <div className="flex min-w-0 items-center gap-2">
                    <span className="truncate text-sm font-medium">
                        {user.username}
                    </span>
                    {user.role === "admin" ? <Badge>管理员</Badge> : null}
                    <Badge variant="outline" title="本用户累计流量">
                        <DownloadIcon className="size-3" />
                        {formatBytes(user.totalBytesServed, 2)}
                    </Badge>
                </div>
            </div>
            {adminMode ? (
                <Button
                    variant="outline"
                    size="icon"
                    onClick={onBack}
                    aria-label="返回文件"
                    title="返回文件"
                >
                    <ArrowLeftIcon className="size-4" />
                </Button>
            ) : user.role === "admin" ? (
                <Button
                    variant="outline"
                    size="icon"
                    onClick={onAdmin}
                    aria-label="用户管理"
                    title="用户管理"
                >
                    <SettingsIcon className="size-4" />
                </Button>
            ) : null}
            <Button
                variant="outline"
                size="icon"
                onClick={onLogout}
                aria-label="退出登录"
                title="退出登录"
            >
                <LogOutIcon className="size-4" />
            </Button>
        </div>
    );
}
