// shared
import { CustomResponse } from "@/app/shared/domain/models/CustomResponse";
import { CustomValidationError } from "@/app/shared/domain/models/ValidationError";
import { JwtService } from "@/app/shared/domain/services/JwtService";
// domain
import { GetByEmailUserRepo } from "@/app/sing-in/domain/repos/GetByEmailUser.repo";
import { SingInRequest } from "@/app/sing-in/domain/models/SingInRequest.model";
import { UserModel } from "@/app/sing-in/domain/models/User.model";
import { JwtWebTokenSignProps } from "@/app/shared/infra/services/JwtWebToken";

export class SingInUseCase {
    constructor(
        private readonly getByEmailUserRepo: GetByEmailUserRepo,
        private readonly jwtService: JwtService,
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
            const jwtWebTokenSignProps: JwtWebTokenSignProps = {
                payload: userModel.props,
                userId: userModel.props.uuid,
            };
            const signResponse = this.jwtService.sign(jwtWebTokenSignProps);
            const SingInResponseProps: SingInResponseProps = {
                auth: {
                    accessToken: signResponse.accessToken,
                    refreshToken: signResponse.refreshToken,
                    tokenType: signResponse.tokenType,
                    expiresIn: signResponse.expiresIn,
                },
                data: {
                    uuid: userModel.props.uuid,
                    fullname: userModel.props.fullname,
                    email: userModel.props.email,
                    role: userModel.props.role,
                }
            }

            return CustomResponse.ok("Sign in successful", SingInResponseProps);

        } catch (error) {
            console.error("Error in CreateUserUseCase:", error);

            if (error instanceof CustomValidationError)
                return error.getCustomResponse();

            return CustomResponse.internalError();
        }
    }
}


export interface SingInRequestProps {
    body: { [key: string]: any }
}

export interface SingInResponseProps {
    auth: {
        accessToken: string;
        refreshToken: string;
        tokenType: string;
        expiresIn: number;
    },
    data: {
        uuid: string;
        fullname: string;
        email: string;
        role: string;
    }
}

