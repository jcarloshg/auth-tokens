
import { UserRequest } from "@/app/create-user/domain/models/UserRequest.model";
import { UserRole } from "@/app/create-user/domain/models/User.model";

describe('UserRequest.model.test.ts', () => {
	let validData: any;

	beforeEach(() => {
		// Arrange: fresh valid data for each test
        const validRole: UserRole = 'ADMIN';
		validData = {
			uuid: '123e4567-e89b-12d3-a456-426614174000',
			fullname: 'John Doe',
			email: 'john.doe@example.com',
			hashedPass: 'supersecretpassword',
			role: validRole,
		};
	});

	it('should create a UserRequest with valid data', () => {
		// Act
		const req = new UserRequest(validData);
		// Assert
		expect(req.props).toEqual(validData);
	});

	it('should throw error for invalid email', () => {
		// Arrange
		validData.email = 'not-an-email';
		// Act & Assert
		expect(() => new UserRequest(validData)).toThrow(/email/);
	});

	it('should throw error for short password', () => {
		// Arrange
		validData.hashedPass = 'short';
		// Act & Assert
		expect(() => new UserRequest(validData)).toThrow(/hashedPass/);
	});

	it('should throw error for empty fullname', () => {
		// Arrange
		validData.fullname = '';
		// Act & Assert
		expect(() => new UserRequest(validData)).toThrow(/fullname/);
	});

	it('should throw error for invalid uuid', () => {
		// Arrange
		validData.uuid = 'not-a-uuid';
		// Act & Assert
		expect(() => new UserRequest(validData)).toThrow(/uuid/);
	});

	it('should throw error for missing required fields', () => {
		// Arrange
		const { email, ...dataWithoutEmail } = validData;
		// Act & Assert
		expect(() => new UserRequest(dataWithoutEmail)).toThrow(/email/);
	});

	it('should throw error for invalid role', () => {
		// Arrange
		validData.role = 'INVALID_ROLE';
		// Act & Assert
		expect(() => new UserRequest(validData)).toThrow(/role|Invalid user role/);
	});
});
