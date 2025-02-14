import express, { Request } from 'express';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { JWT_SECRET } from '@repo/backend-common/config';
import middleware from './middleware';
import {CreateUserSchema, SigninSchema, CreateRoomSchema} from '@repo/common/types';
import {prismaClient} from "@repo/db/client"
import bcrypt from 'bcrypt';

dotenv.config();

const app = express();
app.use(express.json());    

app.post('/signin', async (req, res) => {
    const parsedData = SigninSchema.safeParse(req.body);
    
    if(!parsedData.success){
        res.status(400).json({error: 'Invalid input'});
        return;
    }
    const user = await prismaClient.user.findFirst({
        where:{
            email: parsedData.data.username
        }
    });
    if(!user){
        res.status(404).json({error: 'User not found'});
        return;
    }
    //@ts-ignore
    const valid = await bcrypt.compare(parsedData.data?.password, user.password);
    
    if(!valid){
        res.status(401).json({error: 'Invalid password'});
        return;
    }
    //@ts-ignore
    const token = jwt.sign({ userId: user?.id}, JWT_SECRET);
    res.send({ token });
});

app.post('/signup', async (req, res) => { 
    try {
        const parsedData = CreateUserSchema.safeParse(req.body);
        if(!parsedData.success){
            res.status(400).json({error: 'Invalid input'});
            return;
        }
        const hashedPassword = await bcrypt.hash(parsedData.data.password, 10);
        const user = await prismaClient.user.create({
            data:{
                email: parsedData.data?.username,
                password: hashedPassword,
                name: parsedData.data.name
            }
        })
        res.send({userId: user.id});
    } catch (error) {
        console.log(error);
        res.status(500).json({error: 'Internal server error'});
        
    }
});
//@ts-ignore
app.post('/room', middleware, async (req, res) => {
    try {
        const parsedData = CreateRoomSchema.safeParse(req.body);
        if(!parsedData.success){
            res.status(400).json({error: 'Invalid input'});
            return;
        }
        //@ts-ignore
        const userId = req.userId;
        const room = await prismaClient.room.create({
            data:{
                slug: parsedData.data.name,
                adminId: userId
            }
        });
        res.send({roomId: room.id});
    
    } catch (error) {
        console.log(error);
        res.status(500).json({error: 'Internal server error'});
        
    }
});
app.listen(3001);