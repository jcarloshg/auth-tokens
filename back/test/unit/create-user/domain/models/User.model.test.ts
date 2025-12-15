
import { UserModel, UserModelProps, UserRole } from "@/app/create-user/domain/models/User.model";
import { UserRequest } from "@/app/create-user/domain/models/UserRequest.model";

describe('User.model.test.ts', () => {
    let props: UserModelProps;

    beforeEach(() => {
        // Arrange: fresh valid props for each test
        props = {
            uuid: '123e4567-e89b-12d3-a456-426614174000',
            fullname: 'Jane Doe',
            email: 'jane.doe@example.com',
            hashedPass: 'password123',
            role: 'CUSTOMER' as UserRole,
        };
    });

    it('should construct a UserModel with valid props', () => {
        // Act
        const user = new UserModel(props);
        // Assert
        expect(user.props).toEqual(props);
    });

    it('should create a UserModel from UserRequest', () => {
        // Arrange
        const userRequest = new UserRequest({ ...props });
        // Act
        const user = UserModel.fromUserRequest(userRequest);
        // Assert
        expect(user.props).toEqual(props);
    });

    it('should hash the password using applyHashToPass', () => {
        // Arrange
        const user = new UserModel({ ...props });
        // Act
        user.applyHashToPass();
        // Assert
        expect(user.props.hashedPass).toBe(`hashed_${props.hashedPass}`);
    });

    it('should unhash the password using applyUnHashToPass', () => {
        // Arrange
        const user = new UserModel({ ...props, hashedPass: `hashed_${props.hashedPass}` });
        // Act
        user.applyUnHashToPass();
        // Assert
        expect(user.props.hashedPass).toBe(props.hashedPass);
    });

    it('should not change password if not hashed in applyUnHashToPass', () => {
        // Arrange
        const user = new UserModel({ ...props });
        // Act
        user.applyUnHashToPass();
        // Assert
        expect(user.props.hashedPass).toBe(props.hashedPass);
    });
});
