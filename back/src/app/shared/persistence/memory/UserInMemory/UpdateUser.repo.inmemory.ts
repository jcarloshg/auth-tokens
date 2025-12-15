import { UpdateUserRepo } from "@/app/shared/domain/repos/User/UpdateUser.repo";
import { UserRepoModelProps } from "@/app/shared/domain/repos/User/User.modelRepo";
import * as fs from "fs/promises";
import { USERS_JSON_PATH } from "./utils.inmemory";

export class UpdateUserRepoInMemory implements UpdateUserRepo {
    async execute(user: UserRepoModelProps): Promise<UserRepoModelProps> {
        let users: UserRepoModelProps[] = [];

        // Read existing users, handle file not found gracefully
        try {
            const data = await fs.readFile(USERS_JSON_PATH, "utf-8");
            users = JSON.parse(data);
            if (!Array.isArray(users)) {
                users = [];
            }
        } catch (err: any) {
            if (err.code !== "ENOENT") {
                throw new Error(`Failed to read users data: ${err.message}`);
            }
            // If file does not exist, treat as empty users array
        }

        const index = users.findIndex((u) => u.uuid === user.uuid);
        if (index === -1) {
            throw new Error(`User with id ${user.uuid} not found`);
        }

        users[index] = user;

        // Write updated users array atomically
        const tempPath = `${USERS_JSON_PATH}.tmp`;
        try {
            await fs.writeFile(tempPath, JSON.stringify(users, null, 2), "utf-8");
            await fs.rename(tempPath, USERS_JSON_PATH);
        } catch (err: any) {
            // Clean up temp file if rename fails
            try {
                await fs.unlink(tempPath);
            } catch { }
            throw new Error(`Failed to write users data: ${err.message}`);
        }

        return user;
    }
}
