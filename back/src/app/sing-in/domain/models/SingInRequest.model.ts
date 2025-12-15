
import { ErrosObject, CustomValidationError as CustomValidationError } from '@/app/shared/domain/models/ValidationError';
import { z } from 'zod';

const schema = z.object({
    email: z.email(),
    pass: z.string().min(8),
});

export type SingInRequestProps = z.infer<typeof schema>;

export class SingInRequest {
    public readonly props: SingInRequestProps;

    constructor(data: { [key: string]: any }) {
        const parsed = schema.safeParse(data);
        if (parsed.success === false) {

            const errorMap = new Map<string, string[]>();
            parsed.error.issues.forEach((err: any) => {
                const path = err.path.join('.');
                const messages = errorMap.get(path) || [];
                messages.push(err.message);
                errorMap.set(path, messages);
            });

            const errosObject: ErrosObject = {};
            errorMap.forEach((value, key) => {
                errosObject[key] = value.join(', ');
            });

            throw new CustomValidationError("Invalid data", errosObject);
        }
        this.props = parsed.data;
    }
}
