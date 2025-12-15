
import { UserRepoModelProps } from "@/app/shared/domain/repos/User/User.modelRepo";
import { DeleteUserRepo } from "@/app/shared/domain/repos/User/DeleteUser.repo";

import { usersInMemory } from "../users.memory-data";

export class DeleteUserRepoInMemory implements DeleteUserRepo {
    async execute(id: string): Promise<boolean> {
        const index = usersInMemory.findIndex(u => u.uuid === id);
        if (index === -1) {
            return false;
        }
        usersInMemory.splice(index, 1);
        return true;
    }
}
