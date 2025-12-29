import { CustomResponse } from "@/app/shared/domain/models/CustomResponse";
import { SingInUseCase, SingInRequestProps } from "../domain/sing-in.usecase";
import { GetByEmailUserRepoInMemory } from "../infra/persistence/memory/GetByIdUser.repo.inmemory";
import { JwtWebToken } from "@/app/shared/infra/services/JwtWebToken";

export const singInApplication = async (req: SingInRequestProps): Promise<CustomResponse> => {

    try {

        const getByEmailUserRepo: GetByEmailUserRepoInMemory = new GetByEmailUserRepoInMemory();
        const jwtWebToken: JwtWebToken = new JwtWebToken();

        const useCase = new SingInUseCase(getByEmailUserRepo, jwtWebToken);

        const result = await useCase.execute(req);
        return result;

    } catch (error) {

        return CustomResponse.internalError();

    }
};
