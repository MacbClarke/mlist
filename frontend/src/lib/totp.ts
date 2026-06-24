import { TOTP_CODE_LENGTH } from "@/types";

export function sanitizeTotpCode(value: string) {
    return value.replace(/\D/g, "").slice(0, TOTP_CODE_LENGTH);
}

export function isCompleteTotpCode(value: string) {
    return value.length === TOTP_CODE_LENGTH;
}
