import { Express, Router } from "express";

import { createUserApplication } from "@/app/create-user/application/create-user.application";

export const usersRoutes = (app: Express) => {
    const router = Router();

    router.get('/', (req, res) => {
        // Handle getting all users
        res.send('Get all users endpoint');
    });

    router.get('/:id', (req, res) => {
        // Handle getting user by ID
        res.send(`Get user with ID ${req.params.id} endpoint`);
    });

    router.post('/', async (req, res) => {
        console.log(`req.body: ${JSON.stringify(req.body)}`);
        const customResponse = await createUserApplication(req.body);
        const customResponseProps = customResponse.props;
        res.status(customResponseProps.statusCode).json(customResponseProps);
    });

    router.put('/:id', (req, res) => {
        // Handle updating a user
        res.send(`Update user with ID ${req.params.id} endpoint`);
    });

    router.delete('/:id', (req, res) => {
        // Handle deleting a user
        res.send(`Delete user with ID ${req.params.id} endpoint`);
    });

    app.use('/users', router);
}