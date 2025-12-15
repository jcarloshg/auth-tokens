export type UserRole = "ADMIN" | "AGENT" | "CUSTOMER";
export interface UserRepoModel {
    uuid: string;
    fullname: string;
    email: string;
    hashedPass: string;
    role: UserRole;
}
