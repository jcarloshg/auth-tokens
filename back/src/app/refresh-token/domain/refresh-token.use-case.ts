import { CustomResponse } from "@/app/shared/domain/models/CustomResponse";
import { CustomValidationError } from "@/app/shared/domain/models/ValidationError";
import { GetByIdUserRepo } from "@/app/shared/domain/repos/User/GetByIdUser.repo";
import { JwtService } from "@/app/shared/domain/services/JwtService";

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
        let decoded;
        try {
            decoded = this.JwtService.verifyRefreshToken(props.refreshToken)
        } catch (error) {
            console.error("Error in CreateUserUseCase:", error);
            return CustomResponse.forbidden("Invalid refresh token");
        }

        console.log(`decoded: `, decoded);

        // 3. Generate new tokens
        // const a = this.JwtService.sign

        return CustomResponse.ok("Token refreshed successfully");
    }
}

export interface RefreshTokenUseCaseProps {
    refreshToken: string;
}
