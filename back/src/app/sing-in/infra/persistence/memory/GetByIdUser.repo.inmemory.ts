import { UserRepoModelProps } from "@/app/shared/domain/repos/User/User.modelRepo";
import { usersInMemory } from "@/app/shared/persistence/memory/users.memory-data";
import { GetByEmailUserRepo } from "@/app/sing-in/domain/repos/GetByEmailUser.repo";

export class GetByEmailUserRepoInMemory implements GetByEmailUserRepo {
    async execute(email: string): Promise<UserRepoModelProps | null> {
        const user = usersInMemory.find((u) => u.email === email);
        return user || null;
    }
}
