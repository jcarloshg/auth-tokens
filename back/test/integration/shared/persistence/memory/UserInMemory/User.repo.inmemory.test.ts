import { UserModelRepoInMemory } from "@/app/shared/persistence/memory/UserInMemory/User.repo.inmemory";
import { CreateUserRepoInMemory } from "@/app/shared/persistence/memory/UserInMemory/CreateUser.repo.inmemory";
import { DeleteUserRepoInMemory } from "@/app/shared/persistence/memory/UserInMemory/DeleteUser.repo.inmemory";
import { GetAllUserRepoInMemory } from "@/app/shared/persistence/memory/UserInMemory/GetAllUser.repo.inmemory";
import { GetByIdUserRepoInMemory } from "@/app/shared/persistence/memory/UserInMemory/GetByIdUser.repo.inmemory";
import { UpdateUserRepoInMemory } from "@/app/shared/persistence/memory/UserInMemory/UpdateUser.repo.inmemory";
import { UserModelRepo } from "@/app/shared/domain/repos/User/User.repo";

jest.mock("@/app/shared/persistence/memory/UserInMemory/CreateUser.repo.inmemory");
jest.mock("@/app/shared/persistence/memory/UserInMemory/DeleteUser.repo.inmemory");
jest.mock("@/app/shared/persistence/memory/UserInMemory/GetAllUser.repo.inmemory");
jest.mock("@/app/shared/persistence/memory/UserInMemory/GetByIdUser.repo.inmemory");
jest.mock("@/app/shared/persistence/memory/UserInMemory/UpdateUser.repo.inmemory");

describe("User.repo.inmemory", () => {
	let repo: UserModelRepoInMemory;

	beforeEach(() => {
		jest.clearAllMocks();
		repo = new UserModelRepoInMemory();
	});

	it("should instantiate with all in-memory repos", () => {
		// Arrange
		// (done in beforeEach)

		// Act
		// (instantiation)

		// Assert
		expect(repo).toBeInstanceOf(UserModelRepoInMemory);
		expect(UserModelRepo).toBeDefined();
		expect(CreateUserRepoInMemory).toHaveBeenCalledTimes(1);
		expect(GetAllUserRepoInMemory).toHaveBeenCalledTimes(1);
		expect(GetByIdUserRepoInMemory).toHaveBeenCalledTimes(1);
		expect(UpdateUserRepoInMemory).toHaveBeenCalledTimes(1);
		expect(DeleteUserRepoInMemory).toHaveBeenCalledTimes(1);
	});

	it("should throw if any dependency throws on construction", () => {
		// Arrange
		(CreateUserRepoInMemory as jest.Mock).mockImplementationOnce(() => { throw new Error("fail"); });

		// Act & Assert
		expect(() => new UserModelRepoInMemory()).toThrow("fail");
	});
});
