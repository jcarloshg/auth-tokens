import { GetAllUserRepo } from '@/app/shared/domain/repos/User/GetAllUser.repo';
import { UserRepoModelProps } from '@/app/shared/domain/repos/User/User.modelRepo';

import * as fs from 'fs';
import { USERS_JSON_PATH } from './utils.inmemory';

export class GetAllUserRepoInMemory implements GetAllUserRepo {
    async execute(): Promise<UserRepoModelProps[]> {
        try {
            const data = fs.readFileSync(USERS_JSON_PATH, 'utf-8');
            const users = JSON.parse(data) as UserRepoModelProps[];
            return [...users];
        } catch (err) {
            // If file doesn't exist or is invalid, return empty array
            return [];
        }
    }
}
