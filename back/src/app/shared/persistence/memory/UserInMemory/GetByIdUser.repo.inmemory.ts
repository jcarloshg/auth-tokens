import { GetByIdUserRepo } from "@/app/shared/domain/repos/User/GetByIdUser.repo";
import { UserRepoModelProps } from "@/app/shared/domain/repos/User/User.modelRepo";

import * as fs from 'fs';
import { USERS_JSON_PATH } from "./utils.inmemory";

export class GetByIdUserRepoInMemory implements GetByIdUserRepo {
    async execute(id: string): Promise<UserRepoModelProps | null> {
        try {
            const data = await fs.promises.readFile(USERS_JSON_PATH, 'utf-8');
            const users: UserRepoModelProps[] = JSON.parse(data);
            const user = users.find(u => u.uuid === id);
            return user || null;
        } catch (err: any) {
            // If file doesn't exist, return null; rethrow other errors
            if (err.code === 'ENOENT') {
                return null;
            }
            throw new Error(`Failed to read users data: ${err.message}`);
        }
    }
}
