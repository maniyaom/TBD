import { createHash } from 'crypto';
import ApiError from './ApiError.js';

const hashToken = (token) => {
    if (!token) throw new ApiError("Token is required", 400);

    try {
        return createHash("sha256").update(token).digest("hex");
    } catch(error) {
        throw error;
    }
}

const compareToken = (token, hashedToken) => {
    if (!token) throw new ApiError("Token is required", 400);
    if (!hashedToken) throw new ApiError("Hashed token is required", 400);

    try {
        return hashToken(token) === hashedToken;
    } catch(error) {
        throw error;
    }
}

export { hashToken, compareToken };