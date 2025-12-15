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
            hashedPass: userRequest.props.pass,
            role: userRequest.props.role as UserRole,
        });
    }

    public applyHashToPass() {
        // TODO: Implement password hashing logic here
        // Placeholder for hashing logic
        this.props.hashedPass = `hashed_${this.props.hashedPass}`;
    }

    public applyUnHashToPass() {
        // TODO: Implement password unhashing logic here
        // Placeholder for unhashing logic
        if (this.props.hashedPass.startsWith('hashed_')) {
            this.props.hashedPass = this.props.hashedPass.slice(7);
        }
    }
}


