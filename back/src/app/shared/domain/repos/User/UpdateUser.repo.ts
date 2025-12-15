import { UserRepoModelProps } from "./User.modelRepo";

export class UpdateUserRepo {
    async execute(user: UserRepoModelProps): Promise<UserRepoModelProps> {
        throw new Error("Method to update not implemented.");
    }
}