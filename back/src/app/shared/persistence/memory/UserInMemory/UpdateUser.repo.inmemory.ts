import { UpdateUserRepo } from "@/app/shared/domain/repos/User/UpdateUser.repo";
import { UserRepoModelProps } from "@/app/shared/domain/repos/User/User.modelRepo";
import { usersInMemory } from "../users.memory-data";

export class UpdateUserRepoInMemory implements UpdateUserRepo {
    async execute(user: UserRepoModelProps): Promise<UserRepoModelProps> {
        const index = usersInMemory.findIndex((u) => u.uuid === user.uuid);
        if (index === -1) {
            throw new Error(`User with id ${user.uuid} not found`);
        }
        usersInMemory[index] = user;
        return user;
    }
}
