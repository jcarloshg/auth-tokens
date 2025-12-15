import { UserRepoModelProps } from "./User.modelRepo";

export class GetByIdUserRepo {
    async execute(id: string): Promise<UserRepoModelProps | null> {
        throw new Error("Method to get by id not implemented.");
    }
}
