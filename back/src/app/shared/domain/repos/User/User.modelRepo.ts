import { UserModel } from "@/app/create-user/domain/models/User.model";

export type UserRole = "ADMIN" | "AGENT" | "CUSTOMER";
export interface UserRepoModelProps {
    uuid: string;
    fullname: string;
    email: string;
    hashedPass: string;
    role: UserRole;
}


export class UserRepoModel {
    constructor(
        public readonly props: UserRepoModelProps
    ) { }

    public static fromUserModel(props: UserModel): UserRepoModel {
        return new UserRepoModel({
            uuid: props.props.uuid,
            fullname: props.props.fullname,
            email: props.props.email,
            hashedPass: props.props.hashedPass,
            role: props.props.role,
        });
    }

}