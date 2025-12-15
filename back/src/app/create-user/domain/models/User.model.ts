import { UserRequest } from "./UserRequest.model";

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

    public static fromUserRequest(userRequest: UserRequest): UserModel {
        return new UserModel({
            uuid: userRequest.props.uuid,
            fullname: userRequest.props.fullname,
            email: userRequest.props.email,
            hashedPass: userRequest.props.hashedPass,
            role: userRequest.props.role as UserRole,
        });
    }
}


