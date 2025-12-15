// ===== CreateUser.repo.ts =====
import { UserRepoModel } from "./User.modelRepo";

export class CreateUserRepo {
	async execute(userRepoModel: UserRepoModel): Promise<UserRepoModel> {
		throw new Error("Method to create not implemented.");
	}
}
// ===== DeleteUser.repo.ts =====
export class DeleteUserRepo {
	async execute(id: string): Promise<boolean> {
		throw new Error("Method to delete not implemented.");
	}
}
// ===== GetAllUser.repo.ts =====
import { UserRepoModel } from "./User.modelRepo";

export class GetAllUserRepo {
	async execute(): Promise<UserRepoModel[]> {
		throw new Error("Method to get all not implemented.");
	}
}
// ===== GetByIdUser.repo.ts =====
import { UserRepoModel } from "./User.modelRepo";

export class GetByIdUserRepo {
	async execute(id: string): Promise<UserRepoModel | null> {
		throw new Error("Method to get by id not implemented.");
	}
}
// ===== UpdateUser.repo.ts =====
import { UserRepoModel } from "./User.modelRepo";

export class UpdateUserRepo {
	async execute(user: UserRepoModel): Promise<UserRepoModel> {
		throw new Error("Method to update not implemented.");
	}
}
// ===== User.modelRepo.ts =====
export interface UserRepoModel {}
// ===== User.repo.ts =====
import { CreateUserRepo } from "./CreateUser.repo";
import { DeleteUserRepo } from "./DeleteUser.repo";
import { GetAllUserRepo } from "./GetAllUser.repo";
import { GetByIdUserRepo } from "./GetByIdUser.repo";
import { UpdateUserRepo } from "./UpdateUser.repo";
import { UserRepoModel } from "./User.modelRepo";

export class UserModelRepo {

	constructor(
		private readonly createUserRepo: CreateUserRepo,
		private readonly getAllUserRepo: GetAllUserRepo,
		private readonly getByIdUserRepo: GetByIdUserRepo,
		private readonly updateUserRepo: UpdateUserRepo,
		private readonly deleteUserRepo: DeleteUserRepo,
	) { }

	async create(userRepoModel: UserRepoModel): Promise<UserRepoModel | null> {
		try {
			return await this.createUserRepo.execute(userRepoModel);
		} catch (error) {
			console.error("[UserModelRepo] - [create] error -> ", error);
			return null;
		}
	}

	async getAll(): Promise<UserRepoModel[] | null> {
		try {
			return await this.getAllUserRepo.execute();
		} catch (error) {
			console.error("[UserModelRepo] - [getAll] error -> ", error);
			return null;
		}
	}

	async getById(id: string): Promise<UserRepoModel | null> {
		try {
			return await this.getByIdUserRepo.execute(id);
		} catch (error) {
			console.error("[UserModelRepo] - [getById] error -> ", error);
			return null;
		}
	}

	async update(user: UserRepoModel): Promise<UserRepoModel | null> {
		try {
			return await this.updateUserRepo.execute(user);
		} catch (error) {
			console.error("[UserModelRepo] - [update] error -> ", error);
			return null;
		}
	}

	async delete(id: string): Promise<boolean> {
		try {
			return await this.deleteUserRepo.execute(id);
		} catch (error) {
			console.error("[UserModelRepo] - [delete] error -> ", error);
			return false;
		}
	}


}
