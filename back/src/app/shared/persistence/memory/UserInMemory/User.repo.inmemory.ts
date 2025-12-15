import { CreateUserRepoInMemory } from "./CreateUser.repo.inmemory";
import { DeleteUserRepoInMemory } from "./DeleteUser.repo.inmemory";
import { GetAllUserRepoInMemory } from "./GetAllUser.repo.inmemory";
import { GetByIdUserRepoInMemory } from "./GetByIdUser.repo.inmemory";
import { UpdateUserRepoInMemory } from "./UpdateUser.repo.inmemory";
import { UserModelRepo } from "../../../domain/repos/User/User.repo";

export class UserModelRepoInMemory extends UserModelRepo {
    constructor() {
        super(
            new CreateUserRepoInMemory(),
            new GetAllUserRepoInMemory(),
            new GetByIdUserRepoInMemory(),
            new UpdateUserRepoInMemory(),
            new DeleteUserRepoInMemory()
        );
    }
}
