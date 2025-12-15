import { UserRepoModelProps } from "@/app/shared/domain/repos/User/User.modelRepo";

export type UserRole = "ADMIN" | "AGENT" | "CUSTOMER";

export interface UserModelProps {
    uuid: string;
    fullname: string;
    email: string;
    hashedPass: string;
    role: UserRole;
}

export class UserModel {

    constructor(public readonly props: UserModelProps) { }

    public static fromUserRepo(userRepo: UserRepoModelProps): UserModel {
        return new UserModel({
            uuid: userRepo.uuid,
            fullname: userRepo.fullname,
            email: userRepo.email,
            hashedPass: userRepo.hashedPass,
            role: userRepo.role,
        });
    }

    public applyHashToPass() {
        // TODO: Implement password hashing logic here
        // Placeholder for hashing logic
        this.props.hashedPass = `hashed_${this.props.hashedPass}`;
    }

    public unHashToPass() {
        // TODO: Implement password unhashing logic here
        // Placeholder for unhashing logic
        if (this.props.hashedPass.startsWith('hashed_')) {
            this.props.hashedPass = this.props.hashedPass.slice(7);
        }
    }
}


