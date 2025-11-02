import logger from '../config/logger.js';
import {signUpSchema, signInSchema} from '../validations/auth.validation.js';
import { formatValidationError } from '../utils/format.js';
import { createUser, authenticateUser } from '../services/auth.service.js';
import {jwttoken} from '../utils/jwt.js';
import {cookies} from '../utils/cookies.js';

export const signUp = async (req, res, next) => {
    try {
        const validationResult = signUpSchema.safeParse(req.body);
        if (!validationResult.success) {
            return res.status(400).json({
                error: 'Validation failed',
                details: formatValidationError(validationResult.error)
            })
        }
        const {name, email, password, role} = validationResult.data;

        const user = await createUser(name, email, password, role);

        const token = jwttoken.sign ({id: user.id, email: user.email, role: user.role});

        cookies.set(res, 'token', token);

        logger.info(`Signing up user with email: ${email}`);
        res.status(201).json({
            message: 'User signed up successfully',
            user: {id: user.id, name: user.name, email: user.email, role: user.role}
        });
    } catch (e) {
        logger.error('Error in signUp controller', e);
        if(e.message === 'User with this email already exists') {
            return res.status(409).json({error: 'Email already in use'});
        }
        next(e);
    }
}

export const signIn = async (req, res, next) => {
    try {
        const validationResult = signInSchema.safeParse(req.body);
        if (!validationResult.success) {
            return res.status(400).json({
                error: 'Validation failed',
                details: formatValidationError(validationResult.error)
            })
        }
        const {email, password} = validationResult.data;
        const user = await authenticateUser(email, password);
        if (!user) {
            throw new Error('Invalid credentials');
        }

        const token = jwttoken.sign ({id: user.id, email: user.email, role: user.role});

        cookies.set(res, 'token', token);

        logger.info(`Signing in user with email: ${email}`);

        res.status(200).json({
            message: 'User signed in successfully',
            user: {id: user.id, name: user.name, email: user.email, role: user.role}
    });

    } catch (e) {
        logger.error('Error in signIn controller', e);
        if (e.message === 'Invalid credentials') {
            return res.status(401).json({error: 'Invalid email or password'});
        }
        next(e);
    }

}
export const signOut = (req, res) => {
    cookies.clear(res, 'token');
    logger.info('User logged out');
    res.status(200).json({message: 'Logged out successfully'});
}
