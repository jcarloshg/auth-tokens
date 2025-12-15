import { UserRepoModel } from "./User.modelRepo";

export class GetByIdUserRepo {
    async execute(id: string): Promise<UserRepoModel | null> {
        throw new Error("Method to get by id not implemented.");
    }
}
