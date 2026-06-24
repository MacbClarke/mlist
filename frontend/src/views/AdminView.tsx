import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import {
    ActivityIcon,
    BanIcon,
    CheckCircleIcon,
    KeyRoundIcon,
    Trash2Icon,
    UserPlusIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
    Card,
    CardContent,
} from "@/components/ui/card";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { FormError } from "@/components/FormError";
import { TotpBindingPanel } from "@/components/TotpBindingPanel";
import { AuditView } from "@/views/AuditView";
import { apiJson } from "@/api";
import { formatBytes, formatDate } from "@/lib/format";
import type { TotpBinding, UserRole, UserView, UsersResponse } from "@/types";

export function AdminView({
    currentUser,
    onUserChanged,
}: {
    currentUser: UserView;
    onUserChanged: (user: UserView) => void;
}) {
    const [users, setUsers] = useState<UserView[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [createOpen, setCreateOpen] = useState(false);
    const [binding, setBinding] = useState<TotpBinding | null>(null);
    const [auditUserId, setAuditUserId] = useState("all");

    useEffect(() => {
        void loadUsers();
    }, []);

    async function loadUsers() {
        setLoading(true);
        setError("");
        try {
            const payload = await apiJson<UsersResponse>("/api/admin/users");
            setUsers(payload.users);
        } catch (err) {
            setError(err instanceof Error ? err.message : "用户加载失败");
        } finally {
            setLoading(false);
        }
    }

    async function toggleUser(target: UserView) {
        const action = target.enabled ? "disable" : "enable";
        try {
            const updated = await apiJson<UserView>(
                `/api/admin/users/${target.id}/${action}`,
                {
                    method: "POST",
                },
            );
            setUsers((previous) =>
                previous.map((item) =>
                    item.id === updated.id ? updated : item,
                ),
            );
            if (updated.id === currentUser.id) onUserChanged(updated);
        } catch (err) {
            toast.error(err instanceof Error ? err.message : "操作失败");
        }
    }

    async function resetTotp(target: UserView) {
        try {
            const payload = await apiJson<TotpBinding>(
                `/api/admin/users/${target.id}/reset-totp`,
                {
                    method: "POST",
                },
            );
            setBinding(payload);
            await loadUsers();
        } catch (err) {
            toast.error(err instanceof Error ? err.message : "重置失败");
        }
    }

    async function deleteUser(target: UserView) {
        if (target.id === currentUser.id) {
            toast.error("不能删除当前登录用户。");
            return;
        }
        if (
            !window.confirm(
                `确定删除用户「${target.username}」？相关会话、审计和文件状态也会删除。`,
            )
        ) {
            return;
        }

        try {
            await apiJson<{ ok: boolean }>(`/api/admin/users/${target.id}`, {
                method: "DELETE",
            });
            setUsers((previous) =>
                previous.filter((item) => item.id !== target.id),
            );
            if (auditUserId === String(target.id)) setAuditUserId("all");
            toast.success("用户已删除");
        } catch (err) {
            toast.error(err instanceof Error ? err.message : "删除失败");
        }
    }

    return (
        <div className="space-y-3">
            <div className="flex items-center gap-2">
                <div className="min-w-0 flex-1">
                    <h1 className="text-lg font-semibold">管理</h1>
                    <p className="text-muted-foreground text-sm">
                        用户、资源访问审计和文件流量。
                    </p>
                </div>
            </div>
            {error ? <FormError title="请求失败" message={error} /> : null}
            <Tabs defaultValue="users" className="space-y-3">
                <div className="flex flex-wrap items-center gap-2">
                    <TabsList>
                        <TabsTrigger value="users">
                            <UserPlusIcon className="size-4" />
                            用户
                        </TabsTrigger>
                        <TabsTrigger value="audit">
                            <ActivityIcon className="size-4" />
                            审计
                        </TabsTrigger>
                    </TabsList>
                    <div className="flex-1" />
                    <Button onClick={() => setCreateOpen(true)}>
                        <UserPlusIcon className="size-4" />
                        新建用户
                    </Button>
                </div>
                <TabsContent value="users" className="space-y-3">
                    <Card className="py-1">
                        <CardContent className="p-0">
                            <Table>
                                <TableHeader>
                                    <TableRow>
                                        <TableHead>用户名</TableHead>
                                        <TableHead>角色</TableHead>
                                        <TableHead>状态</TableHead>
                                        <TableHead className="hidden md:table-cell">
                                            最后登录
                                        </TableHead>
                                        <TableHead className="hidden lg:table-cell">
                                            最后使用
                                        </TableHead>
                                        <TableHead className="hidden sm:table-cell">
                                            总流量
                                        </TableHead>
                                        <TableHead className="text-right">
                                            操作
                                        </TableHead>
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {loading ? (
                                        <TableRow>
                                            <TableCell
                                                colSpan={7}
                                                className="text-muted-foreground py-6 text-center"
                                            >
                                                正在加载用户...
                                            </TableCell>
                                        </TableRow>
                                    ) : users.length === 0 ? (
                                        <TableRow>
                                            <TableCell
                                                colSpan={7}
                                                className="text-muted-foreground py-6 text-center"
                                            >
                                                暂无用户
                                            </TableCell>
                                        </TableRow>
                                    ) : (
                                        users.map((item) => (
                                            <TableRow key={item.id}>
                                                <TableCell className="font-medium">
                                                    {item.username}
                                                </TableCell>
                                                <TableCell>
                                                    <Badge
                                                        variant={
                                                            item.role ===
                                                            "admin"
                                                                ? "default"
                                                                : "secondary"
                                                        }
                                                    >
                                                        {item.role === "admin"
                                                            ? "管理员"
                                                            : "用户"}
                                                    </Badge>
                                                </TableCell>
                                                <TableCell>
                                                    <Badge
                                                        variant={
                                                            item.enabled
                                                                ? "outline"
                                                                : "destructive"
                                                        }
                                                    >
                                                        {item.enabled
                                                            ? "启用"
                                                            : "禁用"}
                                                    </Badge>
                                                </TableCell>
                                                <TableCell className="text-muted-foreground hidden md:table-cell">
                                                    {item.lastLoginAt
                                                        ? formatDate(
                                                              item.lastLoginAt,
                                                          )
                                                        : "--"}
                                                </TableCell>
                                                <TableCell className="text-muted-foreground hidden lg:table-cell">
                                                    {item.lastSeenAt
                                                        ? formatDate(
                                                              item.lastSeenAt,
                                                          )
                                                        : "--"}
                                                </TableCell>
                                                <TableCell className="text-muted-foreground hidden sm:table-cell">
                                                    {formatBytes(
                                                        item.totalBytesServed,
                                                    )}
                                                </TableCell>
                                                <TableCell>
                                                    <div className="flex justify-end gap-1">
                                                        <Button
                                                            variant="outline"
                                                            size="icon-sm"
                                                            onClick={() =>
                                                                void resetTotp(
                                                                    item,
                                                                )
                                                            }
                                                            aria-label="重置 TOTP"
                                                            title="重置 TOTP"
                                                        >
                                                            <KeyRoundIcon className="size-4" />
                                                        </Button>
                                                        <Button
                                                            variant="outline"
                                                            size="icon-sm"
                                                            onClick={() =>
                                                                void toggleUser(
                                                                    item,
                                                                )
                                                            }
                                                            aria-label={
                                                                item.enabled
                                                                    ? "禁用用户"
                                                                    : "启用用户"
                                                            }
                                                            title={
                                                                item.enabled
                                                                    ? "禁用用户"
                                                                    : "启用用户"
                                                            }
                                                        >
                                                            {item.enabled ? (
                                                                <BanIcon className="size-4" />
                                                            ) : (
                                                                <CheckCircleIcon className="size-4" />
                                                            )}
                                                        </Button>
                                                        <Button
                                                            variant="outline"
                                                            size="icon-sm"
                                                            onClick={() =>
                                                                void deleteUser(
                                                                    item,
                                                                )
                                                            }
                                                            aria-label="删除用户"
                                                            title="删除用户"
                                                            disabled={
                                                                item.id ===
                                                                currentUser.id
                                                            }
                                                        >
                                                            <Trash2Icon className="size-4" />
                                                        </Button>
                                                    </div>
                                                </TableCell>
                                            </TableRow>
                                        ))
                                    )}
                                </TableBody>
                            </Table>
                        </CardContent>
                    </Card>
                </TabsContent>
                <TabsContent value="audit" className="space-y-3">
                    <AuditView
                        users={users}
                        selectedUserId={auditUserId}
                        onUserChange={setAuditUserId}
                    />
                </TabsContent>
            </Tabs>
            <CreateUserDialog
                open={createOpen}
                onOpenChange={setCreateOpen}
                onCreated={(payload) => {
                    setBinding(payload);
                    setCreateOpen(false);
                    void loadUsers();
                }}
            />
            <BindingDialog binding={binding} onClose={() => setBinding(null)} />
        </div>
    );
}

function CreateUserDialog({
    open,
    onOpenChange,
    onCreated,
}: {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    onCreated: (binding: TotpBinding) => void;
}) {
    const [username, setUsername] = useState("");
    const [role, setRole] = useState<UserRole>("user");
    const [submitting, setSubmitting] = useState(false);
    const [error, setError] = useState("");

    async function submit(event: FormEvent<HTMLFormElement>) {
        event.preventDefault();
        setSubmitting(true);
        setError("");
        try {
            const payload = await apiJson<TotpBinding>("/api/admin/users", {
                method: "POST",
                body: JSON.stringify({ username, role }),
            });
            setUsername("");
            setRole("user");
            onCreated(payload);
        } catch (err) {
            setError(err instanceof Error ? err.message : "创建失败");
        } finally {
            setSubmitting(false);
        }
    }

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent>
                <DialogHeader>
                    <DialogTitle>新建用户</DialogTitle>
                    <DialogDescription>
                        创建后会显示一次 TOTP 绑定二维码。
                    </DialogDescription>
                </DialogHeader>
                <form
                    className="space-y-4"
                    onSubmit={(event) => void submit(event)}
                >
                    <div className="space-y-2">
                        <Label htmlFor="create-username">用户名</Label>
                        <Input
                            id="create-username"
                            value={username}
                            onChange={(event) =>
                                setUsername(event.target.value)
                            }
                            autoFocus
                            required
                        />
                    </div>
                    <div className="space-y-2">
                        <Label>角色</Label>
                        <Select
                            value={role}
                            onValueChange={(value) =>
                                setRole(value as UserRole)
                            }
                        >
                            <SelectTrigger className="w-full">
                                <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectItem value="user">用户</SelectItem>
                                <SelectItem value="admin">管理员</SelectItem>
                            </SelectContent>
                        </Select>
                    </div>
                    {error ? (
                        <FormError title="创建失败" message={error} />
                    ) : null}
                    <DialogFooter>
                        <Button
                            type="button"
                            variant="outline"
                            onClick={() => onOpenChange(false)}
                        >
                            取消
                        </Button>
                        <Button type="submit" disabled={submitting}>
                            {submitting ? "创建中..." : "创建"}
                        </Button>
                    </DialogFooter>
                </form>
            </DialogContent>
        </Dialog>
    );
}

function BindingDialog({
    binding,
    onClose,
}: {
    binding: TotpBinding | null;
    onClose: () => void;
}) {
    return (
        <Dialog
            open={Boolean(binding)}
            onOpenChange={(open) => (!open ? onClose() : undefined)}
        >
            <DialogContent>
                <DialogHeader>
                    <DialogTitle>TOTP 绑定</DialogTitle>
                    <DialogDescription>
                        该二维码和密钥只在本次操作后展示。
                    </DialogDescription>
                </DialogHeader>
                {binding ? <TotpBindingPanel binding={binding} /> : null}
                <DialogFooter>
                    <Button onClick={onClose}>完成</Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}
