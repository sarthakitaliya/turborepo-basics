import { NextFunction, Request, Response } from "express";
import jwt, { JwtPayload } from 'jsonwebtoken';
import { JWT_SECRET } from '@repo/backend-common/config';


interface Decoded extends JwtPayload{
    userId: number;
}
export default function middleware(req: Request, res: Response, next: NextFunction){
    try {

        const token = req.headers["authorization"] ?? "" ;
        
        if(!token) {
            return res.status(401).send({ message: "No token provided" });
        }
        const decoded = jwt.verify(token, JWT_SECRET as string) as Decoded;
        
        if(decoded) {
            req.userId = decoded.userId;
            next();
        }else{
            return res.status(401).send({ message: "Unauthorized" });
        }
    } catch (error) {
        
    }
}