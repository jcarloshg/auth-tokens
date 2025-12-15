
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
			pass: 'supersecretpassword',
			role: validRole,
		};
	});

	it('should create a UserRequest with valid data', () => {
		// Act
		const req = new UserRequest(validData);
		// Assertw
		expect(req.props).toEqual(validData);
	});

	it('should throw error for invalid email', () => {
		// Arrange
		validData.email = 'not-an-email';
		// Act & Assert
		try {
			new UserRequest(validData);
			fail('Expected ValidationError');
		} catch (err: any) {
			expect(err).toBeInstanceOf(Error);
			const details = err.getCustomResponse().props.data;
			expect(details).toBeDefined();
			expect(Object.keys(details)).toContain('email');
		}
	});

	it('should throw error for short password', () => {
		// Arrange
		validData.pass = 'short';
		// Act & Assert
		try {
			new UserRequest(validData);
			fail('Expected ValidationError');
		} catch (err: any) {
			expect(err).toBeInstanceOf(Error);
			const details = err.getCustomResponse().props.data;
			expect(details).toBeDefined();
			expect(Object.keys(details)).toContain('pass');
		}
	});

	it('should throw error for empty fullname', () => {
		// Arrange
		validData.fullname = '';
		// Act & Assert
		try {
			new UserRequest(validData);
			fail('Expected ValidationError');
		} catch (err: any) {
			expect(err).toBeInstanceOf(Error);
			const details = err.getCustomResponse().props.data;
			expect(details).toBeDefined();
			expect(Object.keys(details)).toContain('fullname');
		}
	});

	it('should throw error for invalid uuid', () => {
		// Arrange
		validData.uuid = 'not-a-uuid';
		// Act & Assert
		try {
			new UserRequest(validData);
			fail('Expected ValidationError');
		} catch (err: any) {
			expect(err).toBeInstanceOf(Error);
			const details = err.getCustomResponse().props.data;
			expect(details).toBeDefined();
			expect(Object.keys(details)).toContain('uuid');
		}
	});

	it('should throw error for missing required fields', () => {
		// Arrange
		const { email, ...dataWithoutEmail } = validData;
		// Act & Assert
		try {
			new UserRequest(dataWithoutEmail);
			fail('Expected ValidationError');
		} catch (err: any) {
			expect(err).toBeInstanceOf(Error);
			const details = err.getCustomResponse().props.data;
			expect(details).toBeDefined();
			expect(Object.keys(details)).toContain('email');
		}
	});

	it('should throw error for invalid role', () => {
		// Arrange
		validData.role = 'INVALID_ROLE';
		// Act & Assert
		try {
			new UserRequest(validData);
			fail('Expected ValidationError');
		} catch (err: any) {
			expect(err).toBeInstanceOf(Error);
			const details = err.getCustomResponse().props.data;
			expect(details).toBeDefined();
			expect(Object.keys(details)).toContain('role');
		}
	});
});
