import { CustomResponse } from "@/app/shared/domain/models/CustomResponse";
import { CustomValidationError } from "@/app/shared/domain/models/ValidationError";
import { GetByIdUserRepo } from "@/app/shared/domain/repos/User/GetByIdUser.repo";
import { JwtService, VerifyObject } from "@/app/shared/domain/services/JwtService";
import { JwtWebTokenSignProps } from "@/app/shared/infra/services/JwtWebToken";

export class RefreshTokenUseCase {

    constructor(
        private readonly GetByIdUserRepo: GetByIdUserRepo,
        private readonly JwtService: JwtService
    ) { }

    public async execute(props: RefreshTokenUseCaseProps): Promise<CustomResponse> {

        // 1. validate input
        if (props.refreshToken.length === 0)
            return CustomResponse.forbidden("Refresh token is required");

        // 2. verify refresh token
        let decoded: VerifyObject;
        try {
            decoded = this.JwtService.verifyRefreshToken(props.refreshToken)
        } catch (error) {
            console.error("Error in CreateUserUseCase:", error);
            return CustomResponse.forbidden("Invalid refresh token");
        }

        // 3. found user
        const user = await this.GetByIdUserRepo.execute(decoded.userId);
        if (!user) {
            return CustomResponse.internalError();
        }

        // 4. Generate new tokens
        const jwtWebTokenSignProps: JwtWebTokenSignProps = {
            payload: user,
            userId: user.uuid
        }
        const signResponse = this.JwtService.sign(jwtWebTokenSignProps);

        const response: RefreshTokenUseCaseResponse = {
            auth: {
                accessToken: signResponse.accessToken,
                refreshToken: signResponse.refreshToken,
                tokenType: signResponse.tokenType,
                expiresIn: signResponse.expiresIn,
            },
            data: {
                uuid: user.uuid,
                fullname: user.fullname,
                email: user.email,
                role: user.role,
            }
        }

        return CustomResponse.ok("Token refreshed successfully", response);
    }
}

export interface RefreshTokenUseCaseProps {
    refreshToken: string;
}


export interface RefreshTokenUseCaseResponse {
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