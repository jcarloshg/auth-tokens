import { CreateUserRepoInMemory } from "@/app/shared/persistence/memory/UserInMemory/CreateUser.repo.inmemory";
import { UserRepoModelProps } from "@/app/shared/domain/repos/User/User.modelRepo";

describe('CreateUser.repo.inmemory (integration)', () => {

	let repo: CreateUserRepoInMemory;
	let mockUser: UserRepoModelProps;

	beforeAll(() => { });

	beforeEach(() => {
		repo = new CreateUserRepoInMemory();
		mockUser = {
			uuid: crypto.randomUUID(),
			fullname: 'User 1',
			email: 'user1@example.com',
			hashedPass: 'hashedpassword1',
			role: 'ADMIN',
		}
	});

	it('should create and return the user', async () => {
		// Act
		const result = await repo.execute(mockUser);

		// Assert
		expect(result).toEqual(mockUser);
	})


});
