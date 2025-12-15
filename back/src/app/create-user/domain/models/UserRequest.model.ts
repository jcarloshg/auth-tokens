import { z } from 'zod';
import { CustomValidationError } from '@/app/shared/domain/models/ValidationError';

const userSchema = z.object({
    uuid: z.uuid(),
    fullname: z.string().min(1).max(100),
    email: z.email(),
    pass: z.string().min(8),
    role: z.enum(["ADMIN", "AGENT", "CUSTOMER"]),
});

export type UserRequestProps = z.infer<typeof userSchema>;

export class UserRequest {
    public readonly props: UserRequestProps;

    constructor(data: { [key: string]: any }) {
        const parsed = userSchema.safeParse(data);
        if (!parsed.success) {
            // const errorMessage = parsed.error.issues.map((err: any) => `${err.path.join('.')}: ${err.message}`)[0];

            const errorMap = new Map<string, string[]>();
            parsed.error.issues.forEach((err: any) => {
                const path = err.path.join('.');
                const messages = errorMap.get(path) || [];
                messages.push(err.message);
                errorMap.set(path, messages);
            });

            const errosObject: { [key: string]: string } = {};
            errorMap.forEach((value, key) => {
                errosObject[key] = value.join(', ');
            });
            throw new CustomValidationError("Invalid user data", errosObject);
        }
        this.props = parsed.data;
    }
}