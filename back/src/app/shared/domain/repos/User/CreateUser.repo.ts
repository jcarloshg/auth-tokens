import { UserRepoModel } from "./User.modelRepo";

export class CreateUserRepo {
    async execute(userRepoModel: UserRepoModel): Promise<UserRepoModel> {
        throw new Error("Method to create not implemented.");
    }
}
