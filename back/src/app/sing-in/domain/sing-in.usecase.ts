import { CustomResponse } from "@/app/shared/domain/models/CustomResponse";
import { GetByEmailUserRepo } from "./repos/GetByEmailUser.repo";
import { SingInRequest } from "./models/SingInRequest.model";
import { CustomValidationError } from "@/app/shared/domain/models/ValidationError";
import { UserModel } from "@/app/sing-in/domain/models/User.model";

export class SingInUseCase {
    constructor(
        private readonly getByEmailUserRepo: GetByEmailUserRepo,
    ) { }

    async execute(req: SingInRequestProps): Promise<CustomResponse> {
        try {

            // 1. valid data 
            const validData: SingInRequest = new SingInRequest(req.body);

            // 2. check if the user exists
            const userEmail = validData.props.email;
            const userRepo = await this.getByEmailUserRepo.execute(userEmail);
            if (!userRepo) {
                return CustomResponse.notFound("User does not exist");
            }

            // 3. unhash the stored password
            const userModel: UserModel = UserModel.fromUserRepo(userRepo);
            userModel.unHashToPass();

            // 3. compare with the provided password
            if (userModel.props.hashedPass !== validData.props.pass) {
                return CustomResponse.unauthorized("Invalid credentials");
            }

            // 4. generate a token if valid
            const SingInResponseProps: SingInResponseProps = {
                token: "generated_jwt_token_placeholder",
                refreshToken: "generated_refresh_token_placeholder",
                data: {
                    uuid: userModel.props.uuid,
                    fullname: userModel.props.fullname,
                    email: userModel.props.email,
                    role: userModel.props.role,
                }
            }

            // 5. generate refresh token if valid

            return CustomResponse.ok("Sign in successful", SingInResponseProps);

        } catch (error) {
            console.error("Error in CreateUserUseCase:", error);
            if (error instanceof CustomValidationError) {
                return error.getCustomResponse();
            }
            return CustomResponse.internalError();
        }
    }
}


export interface SingInRequestProps {
    body: { [key: string]: any }
}

export interface SingInResponseProps {
    token: string;
    refreshToken: string;
    data: {
        uuid: string;
        fullname: string;
        email: string;
        role: string;
    }
}

