import { CreateUserRepo } from "@/app/shared/domain/repos/User/CreateUser.repo";
import { UserRepoModelProps } from "@/app/shared/domain/repos/User/User.modelRepo";

import * as fs from 'fs';
import * as path from 'path';
import { USERS_JSON_PATH } from "./utils.inmemory";


export class CreateUserRepoInMemory implements CreateUserRepo {
    async execute(userRepoModel: UserRepoModelProps): Promise<UserRepoModelProps> {
        let users: UserRepoModelProps[] = [];

        // Read existing users, handle file not found gracefully
        try {
            const data = await fs.promises.readFile(USERS_JSON_PATH, 'utf-8');
            users = JSON.parse(data);
            if (!Array.isArray(users)) {
                users = [];
            }
        } catch (err: any) {
            if (err.code !== 'ENOENT') {
                throw new Error(`Failed to read users data: ${err.message}`);
            }
        }

        users.push(userRepoModel);

        // Write updated users array atomically
        try {
            const tempPath = `${USERS_JSON_PATH}.tmp`;
            await fs.promises.writeFile(tempPath, JSON.stringify(users, null, 2), 'utf-8');
            // await fs.promises.rename(tempPath, USERS_JSON_PATH);
        } catch (err: any) {
            throw new Error(`Failed to write users data: ${err.message}`);
        }

        return userRepoModel;
    }
}
