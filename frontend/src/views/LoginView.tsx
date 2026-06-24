import { useState } from "react";
import type { FormEvent } from "react";
import { AlertCircleIcon, KeyRoundIcon } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
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
import { isCompleteTotpCode } from "@/lib/totp";
import { TotpCodeInput } from "@/components/TotpCodeInput";

export function LoginView({
    onLogin,
}: {
    onLogin: (username: string, code: string) => Promise<void>;
}) {
    const [username, setUsername] = useState("");
    const [code, setCode] = useState("");
    const [submitting, setSubmitting] = useState(false);
    const [error, setError] = useState("");

    async function submit(event: FormEvent<HTMLFormElement>) {
        event.preventDefault();
        setError("");
        if (!isCompleteTotpCode(code)) {
            setError("请输入 6 位动态码。");
            return;
        }
        setSubmitting(true);
        try {
            await onLogin(username, code);
        } catch (err) {
            setError(err instanceof Error ? err.message : "登录失败");
        } finally {
            setSubmitting(false);
        }
    }

    return (
        <div className="mx-auto max-w-sm pt-16">
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <KeyRoundIcon className="size-5" />
                        登录
                    </CardTitle>
                    <CardDescription>
                        使用用户名和 6 位动态码访问文件。
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    <form
                        className="space-y-4"
                        onSubmit={(event) => void submit(event)}
                    >
                        <div className="space-y-2">
                            <Label htmlFor="login-username">用户名</Label>
                            <Input
                                id="login-username"
                                value={username}
                                onChange={(event) =>
                                    setUsername(event.target.value)
                                }
                                autoFocus
                                required
                            />
                        </div>
                        <div className="space-y-2">
                            <Label htmlFor="login-code">动态码</Label>
                            <TotpCodeInput
                                id="login-code"
                                value={code}
                                onChange={setCode}
                            />
                        </div>
                        {error ? (
                            <Alert variant="destructive">
                                <AlertCircleIcon className="size-4" />
                                <AlertTitle>登录失败</AlertTitle>
                                <AlertDescription>{error}</AlertDescription>
                            </Alert>
                        ) : null}
                        <Button
                            type="submit"
                            className="w-full"
                            disabled={submitting}
                        >
                            {submitting ? "登录中..." : "登录"}
                        </Button>
                    </form>
                </CardContent>
            </Card>
        </div>
    );
}
