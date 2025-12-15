import { z } from 'zod';

const userSchema = z.object({
    uuid: z.uuid(),
    fullname: z.string().min(1).max(100),
    email: z.email(),
    hashedPass: z.string().min(8),
    role: z.string().min(1).max(50),
});

export type UserRequestProps = z.infer<typeof userSchema>;

export class UserRequest {
    public readonly props: UserRequestProps;

    constructor(data: { [key: string]: any }) {
        const parsed = userSchema.safeParse(data);
        if (!parsed.success) {
            const errorMessage = parsed.error.issues.map((err: any) => `${err.path.join('.')}: ${err.message}`)[0];
            throw new Error(errorMessage);
        }
        this.props = parsed.data;
    }
}