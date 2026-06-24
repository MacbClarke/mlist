import { CopyIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { UserView } from "@/types";

export function TotpBindingPanel({
    binding,
}: {
    binding: {
        username?: string;
        secret: string;
        otpauthUrl: string;
        qrDataUrl: string;
        user?: UserView;
    };
}) {
    const label = binding.user?.username ?? binding.username ?? "user";

    async function copySecret() {
        try {
            await navigator.clipboard.writeText(binding.secret);
            toast.success("密钥已复制");
        } catch {
            toast.error("复制失败，请检查浏览器剪贴板权限。");
        }
    }

    return (
        <div className="space-y-3">
            <div className="flex justify-center rounded-md border bg-white p-4">
                <img
                    src={binding.qrDataUrl}
                    alt={`${label} TOTP QR`}
                    className="size-48"
                />
            </div>
            <div className="space-y-2">
                <Label>密钥</Label>
                <div className="flex gap-2">
                    <Input
                        value={binding.secret}
                        readOnly
                        className="font-mono text-xs"
                    />
                    <Button
                        type="button"
                        variant="outline"
                        size="icon"
                        onClick={() => void copySecret()}
                    >
                        <CopyIcon className="size-4" />
                    </Button>
                </div>
            </div>
        </div>
    );
}
