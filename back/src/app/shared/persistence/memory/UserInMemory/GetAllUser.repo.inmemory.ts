import { GetAllUserRepo } from '@/app/shared/domain/repos/User/GetAllUser.repo';
import { UserRepoModelProps } from '@/app/shared/domain/repos/User/User.modelRepo';

import { usersInMemory } from '../users.memory-data';

export class GetAllUserRepoInMemory implements GetAllUserRepo {
    async execute(): Promise<UserRepoModelProps[]> {
        return [...usersInMemory];
    }
}
