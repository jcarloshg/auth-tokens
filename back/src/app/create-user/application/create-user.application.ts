import { UserModelRepoInMemory } from "@/app/shared/persistence/memory/UserInMemory/User.repo.inmemory"
import { CreateUserUseCase, RequestData } from "../domain/create-user.use-case"
import { CustomResponse } from "@/app/shared/domain/models/CustomResponse";

export const createUserApplication = async (body: { [key: string]: any }): Promise<CustomResponse> => {
    try {
        const repo: UserModelRepoInMemory = new UserModelRepoInMemory()
        const userCase: CreateUserUseCase = new CreateUserUseCase(repo);
        const requestData: RequestData = {
            body: body
        }
        const result = await userCase.execute(requestData);
        return result;

    } catch (error) {
        console.error("Error in createUserApplication:", error);
        return CustomResponse.internalError();
    }
}