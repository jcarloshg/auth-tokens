import { CreateUserRepo } from "@/app/shared/domain/repos/User/CreateUser.repo";
import { UserRepoModelProps } from "@/app/shared/domain/repos/User/User.modelRepo";
import { usersInMemory } from "../users.memory-data";

export class CreateUserRepoInMemory implements CreateUserRepo {
    async execute(
        userRepoModel: UserRepoModelProps
    ): Promise<UserRepoModelProps> {
        try {
            usersInMemory.push(userRepoModel);
            return userRepoModel;
        } catch (error) {
            throw new Error(
                `Failed to create user in memory: ${(error as Error).message}`
            );
        }
    }
}
