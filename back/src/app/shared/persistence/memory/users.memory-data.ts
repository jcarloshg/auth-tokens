import { UserRepoModelProps } from "../../domain/repos/User/User.modelRepo";

export const usersInMemory: UserRepoModelProps[] = [
  {
    "uuid": "123e4567-e89b-12d3-a456-426614174000",
    "fullname": "John Doe",
    "email": "Jhon@email.com",
    "hashedPass": "hashed_password123",
    "role": "ADMIN"
  },
  {
    "uuid": "223e4567-e89b-12d3-a456-426614174001",
    "fullname": "Alice Smith",
    "email": "alice@email.com",
    "hashedPass": "hashed_password456",
    "role": "ADMIN"
  },
  {
    "uuid": "323e4567-e89b-12d3-a456-426614174002",
    "fullname": "Bob Johnson",
    "email": "bob@email.com",
    "hashedPass": "hashed_password789",
    "role": "ADMIN"
  }
]
