import { REGEXP_ONLY_DIGITS } from "input-otp";

import {
    InputOTP,
    InputOTPGroup,
    InputOTPSeparator,
    InputOTPSlot,
} from "@/components/ui/input-otp";
import { TOTP_CODE_LENGTH } from "@/types";
import { sanitizeTotpCode } from "@/lib/totp";

export function TotpCodeInput({
    id,
    value,
    onChange,
}: {
    id: string;
    value: string;
    onChange: (value: string) => void;
}) {
    const handleChange = (nextValue: string) => {
        onChange(sanitizeTotpCode(nextValue));
    };

    return (
        <InputOTP
            id={id}
            maxLength={TOTP_CODE_LENGTH}
            value={value}
            onChange={handleChange}
            pasteTransformer={sanitizeTotpCode}
            pattern={REGEXP_ONLY_DIGITS}
            inputMode="numeric"
            autoComplete="one-time-code"
            required
        >
            <InputOTPGroup>
                <InputOTPSlot index={0} />
                <InputOTPSlot index={1} />
                <InputOTPSlot index={2} />
            </InputOTPGroup>
            <InputOTPSeparator />
            <InputOTPGroup>
                <InputOTPSlot index={3} />
                <InputOTPSlot index={4} />
                <InputOTPSlot index={5} />
            </InputOTPGroup>
        </InputOTP>
    );
}
