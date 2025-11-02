import bcrypt from 'bcrypt';
import logger from '../config/logger.js';
import { db } from '../config/database.js';
import { users } from '../models/user.model.js';
import { eq } from 'drizzle-orm';

export const hashPassword = async password => {
  try {
    return await bcrypt.hash(password, 10);
  } catch (e) {
    logger.error('Error hashing password', e);
    throw new Error('Password hashing failed');
  }
};

export const comparePassword = async (password, hash) => {
  try {
    return await bcrypt.compare(password, hash);
  } catch (e) {
    logger.error('Error comparing password', e);
    throw new Error('Password comparison failed');
  }
};

export const authenticateUser = async (email, password) => {
  try {
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);
    if (!user) {
      return null;
    }
    const isPasswordValid = await comparePassword(password, user.password);
    if (!isPasswordValid) {
      return null;
    }
    return { id: user.id, name: user.name, email: user.email, role: user.role };
  } catch (e) {
    logger.error('Error authenticating user', e);
    throw e;
  }
};

export const createUser = async (name, email, password, role = 'user') => {
  try {
    const existingUser = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);
    if (existingUser.length > 0)
      throw new Error('User with this email already exists');

    const password_hash = await hashPassword(password);

    const [newUser] = await db
      .insert(users)
      .values({ name, email, password: password_hash, role })
      .returning({
        id: users.id,
        name: users.name,
        email: users.email,
        role: users.role,
        created_at: users.created_at,
      });

    logger.info(`User created with email: ${email}`);
    return newUser;
  } catch (e) {
    logger.error('Error creating user', e);
    throw e;
  }
};
