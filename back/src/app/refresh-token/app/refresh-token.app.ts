import { GetByEmailUserRepoInMemory } from "@/app/sing-in/infra/persistence/memory/GetByIdUser.repo.inmemory";
import { RefreshTokenUseCase, RefreshTokenUseCaseProps } from "../domain/refresh-token.use-case"
import { JwtWebToken } from "@/app/shared/infra/services/JwtWebToken";
import { GetByIdUserRepoInMemory } from "@/app/shared/persistence/memory/UserInMemory/GetByIdUser.repo.inmemory";
import { CustomResponse } from "@/app/shared/domain/models/CustomResponse";

export const refreshTokenApplication = async (props: RefreshTokenUseCaseProps): Promise<CustomResponse> => {
    try {

        const getByIdUserRepo: GetByIdUserRepoInMemory = new GetByIdUserRepoInMemory();
        const jwtWebToken: JwtWebToken = new JwtWebToken();

        const refreshTokenUseCase = new RefreshTokenUseCase(
            getByIdUserRepo,
            jwtWebToken
        );

        const result = await refreshTokenUseCase.execute(props);
        return result;

    } catch (error) {

        return CustomResponse.internalError();

    }
}