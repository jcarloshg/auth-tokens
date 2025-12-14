import express, { Express, Request, Response } from 'express';


export const healthRoutes = (app: Express) => {
    app.get('/', (req: Request, res: Response) => {
        res.json({
            message: "👋 Welcome to the Auth Token API!",
            status: "success",
            timestamp: new Date().toISOString()
        });
    });
}