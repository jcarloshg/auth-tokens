
import { UserRepoModelProps } from "@/app/shared/domain/repos/User/User.modelRepo";
import { DeleteUserRepo } from "@/app/shared/domain/repos/User/DeleteUser.repo";

import * as fs from 'fs';
import { USERS_JSON_PATH } from "./utils.inmemory";

export class DeleteUserRepoInMemory implements DeleteUserRepo {
    async execute(id: string): Promise<boolean> {
        let users: UserRepoModelProps[] = [];
        try {
            const data = await fs.promises.readFile(USERS_JSON_PATH, 'utf-8');
            users = JSON.parse(data);
        } catch (err: any) {
            // If file doesn't exist, treat as empty; rethrow other errors
            if (err.code !== 'ENOENT') {
                throw err;
            }
        }

        const index = users.findIndex(u => u.uuid === id);
        if (index === -1) {
            return false;
        }

        users.splice(index, 1);

        try {
            await fs.promises.writeFile(USERS_JSON_PATH, JSON.stringify(users, null, 2), 'utf-8');
        } catch (err) {
            // Optionally log error or handle as needed
            throw err;
        }

        return true;
    }
}
