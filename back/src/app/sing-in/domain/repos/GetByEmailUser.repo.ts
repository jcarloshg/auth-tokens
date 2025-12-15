import { UserRepoModelProps } from "@/app/shared/domain/repos/User/User.modelRepo";

export class GetByEmailUserRepo {
    async execute(email: string): Promise<UserRepoModelProps | null> {
        throw new Error("Method to get by email not implemented.");
    }
}
