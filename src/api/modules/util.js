import jwt from 'jsonwebtoken';
import * as bcryptjs from 'bcryptjs';
import {devConfig} from '../../config/env/development';

export const getJWTToken = payload => {
    return jwt.sign(payload, devConfig.secret, {
        expiresIn: '1d',
    });
};
export const getEncryptedPassword = async password => {
    const salt = await bcryptjs.genSalt();
    return await bcryptjs.hash(password, salt);
};
