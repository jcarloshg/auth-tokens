import { Request, Response } from "express";



export const RefreshController = async (req: Request, res: Response) => {

    console.log(`req.: `, req.cookies);
    
}