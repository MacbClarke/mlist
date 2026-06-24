import { useState } from "react";
import type { FormEvent } from "react";
import { ShieldIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { FormError } from "@/components/FormError";
import { isCompleteTotpCode } from "@/lib/totp";
import { TotpCodeInput } from "@/components/TotpCodeInput";
import { TotpBindingPanel } from "@/components/TotpBindingPanel";
import { apiJson } from "@/api";
import type { BootstrapStartResponse } from "@/types";

export function BootstrapView({
    onFinish,
}: {
    onFinish: (username: string, secret: string, code: string) => Promise<void>;
}) {
    const [username, setUsername] = useState("");
    const [code, setCode] = useState("");
    const [binding, setBinding] = useState<BootstrapStartResponse | null>(null);
    const [submitting, setSubmitting] = useState(false);
    const [error, setError] = useState("");

    async function start(event: FormEvent<HTMLFormElement>) {
        event.preventDefault();
        setSubmitting(true);
        setError("");
        try {
            const payload = await apiJson<BootstrapStartResponse>(
                "/api/bootstrap/start",
                {
                    method: "POST",
                    body: JSON.stringify({ username }),
                },
            );
            setBinding(payload);
        } catch (err) {
            setError(err instanceof Error ? err.message : "初始化失败");
        } finally {
            setSubmitting(false);
        }
    }

    async function finish(event: FormEvent<HTMLFormElement>) {
        event.preventDefault();
        if (!binding) return;
        setError("");
        if (!isCompleteTotpCode(code)) {
            setError("请输入 6 位动态码。");
            return;
        }
        setSubmitting(true);
        try {
            await onFinish(binding.username, binding.secret, code);
        } catch (err) {
            setError(err instanceof Error ? err.message : "动态码验证失败");
        } finally {
            setSubmitting(false);
        }
    }

    return (
        <div className="mx-auto max-w-md pt-10">
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <ShieldIcon className="size-5" />
                        初始化管理员
                    </CardTitle>
                    <CardDescription>
                        空库首次绑定的账号会成为管理员。
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    {!binding ? (
                        <form
                            className="space-y-4"
                            onSubmit={(event) => void start(event)}
                        >
                            <div className="space-y-2">
                                <Label htmlFor="bootstrap-username">
                                    管理员用户名
                                </Label>
                                <Input
                                    id="bootstrap-username"
                                    value={username}
                                    onChange={(event) =>
                                        setUsername(event.target.value)
                                    }
                                    autoFocus
                                    required
                                />
                            </div>
                            {error ? (
                                <FormError title="初始化失败" message={error} />
                            ) : null}
                            <Button
                                type="submit"
                                className="w-full"
                                disabled={submitting}
                            >
                                {submitting ? "生成中..." : "生成 TOTP"}
                            </Button>
                        </form>
                    ) : (
                        <form
                            className="space-y-4"
                            onSubmit={(event) => void finish(event)}
                        >
                            <TotpBindingPanel binding={binding} />
                            <div className="space-y-2">
                                <Label htmlFor="bootstrap-code">动态码</Label>
                                <TotpCodeInput
                                    id="bootstrap-code"
                                    value={code}
                                    onChange={setCode}
                                />
                            </div>
                            {error ? (
                                <FormError title="验证失败" message={error} />
                            ) : null}
                            <Button
                                type="submit"
                                className="w-full"
                                disabled={submitting}
                            >
                                {submitting ? "验证中..." : "完成初始化"}
                            </Button>
                        </form>
                    )}
                </CardContent>
            </Card>
        </div>
    );
}
