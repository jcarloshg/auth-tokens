import { CustomResponse } from "@/app/shared/domain/models/CustomResponse";
import { UserModel } from "./models/User.model";
import { UserRequest } from "./models/UserRequest.model";
import { UserRepoModel } from "@/app/shared/domain/repos/User/User.modelRepo";
import { UserModelRepo } from "@/app/shared/domain/repos/User/User.repo";
import { CustomValidationError } from "@/app/shared/domain/models/ValidationError";


export class CreateUserUseCase {

    constructor(
        private readonly userModelRepo: UserModelRepo,
    ) { }

    async execute(userData: RequestData): Promise<CustomResponse> {

        try {

            // 1. valid if the email is already in use
            const userRequest = new UserRequest(userData.body);

            // 2. hash the password
            const userModel: UserModel = UserModel.fromUserRequest(userRequest);
            userModel.applyHashToPass();

            // 3. save the user to the database
            const userRepoModel = UserRepoModel.fromUserModel(userModel);
            const createdUser = await this.userModelRepo.create(userRepoModel.props);
            if (createdUser == null) {
                return CustomResponse.badRequest('Error creating user');
            }

            // 4. send a welcome email
            console.log(`sending email to`, createdUser.email);

            return CustomResponse.create(createdUser, "User created successfully");


        } catch (error) {
            console.error("Error in CreateUserUseCase:", error);
            if (error instanceof CustomValidationError) {
                return error.getCustomResponse();
            }
            return CustomResponse.internalError();
        }
    }
}

export interface RequestData {
    body: { [key: string]: any }
}