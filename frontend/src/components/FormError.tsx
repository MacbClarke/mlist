import { AlertCircleIcon } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

export function FormError({ title, message }: { title: string; message: string }) {
    return (
        <Alert variant="destructive">
            <AlertCircleIcon className="size-4" />
            <AlertTitle>{title}</AlertTitle>
            <AlertDescription>{message}</AlertDescription>
        </Alert>
    );
}
