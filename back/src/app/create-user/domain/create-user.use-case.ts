import { UserModel } from "./models/User.model";
import { UserRequest } from "./models/UserRequest.model";

export class CreateUserUseCase {

    constructor() { }

    async execute(userData: any): Promise<void> {

        try {

            // 1. valid if the email is already in use
            const userRequest = new UserRequest(userData.body);

            // 2. hash the password
            const userModel: UserModel = UserModel.fromUserRequest(userRequest);
            userModel.applyHashToPass();

            // 3. save the user to the database
            // 4. send a welcome email

        } catch (error) {

        }
    }
}

export interface RequestData {
    body: { [key: string]: any }
}