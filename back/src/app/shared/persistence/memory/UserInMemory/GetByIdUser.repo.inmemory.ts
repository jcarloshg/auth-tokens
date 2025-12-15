import { GetByIdUserRepo } from "@/app/shared/domain/repos/User/GetByIdUser.repo";
import { UserRepoModelProps } from "@/app/shared/domain/repos/User/User.modelRepo";

import { usersInMemory } from "../users.memory-data";

export class GetByIdUserRepoInMemory implements GetByIdUserRepo {
    async execute(id: string): Promise<UserRepoModelProps | null> {
        const user = usersInMemory.find(u => u.uuid === id);
        return user || null;
    }
}
