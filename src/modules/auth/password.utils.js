import bcrypt from "bcrypt";
import ApiError from "../../utils/ApiError.js";

const SALT_ROUNDS = 12;
async function hashPassword(password) {
    try {
        return await bcrypt.hash(password, SALT_ROUNDS);
    } catch (error) {
        throw new ApiError("Failed to hash password", 500);
    }
}

async function comparePassword(password, hashedPassword) {
    try {
        return await bcrypt.compare(password, hashedPassword);
    } catch (error) {
        throw new ApiError("Failed to compare password", 500);
    }
}

export { hashPassword, comparePassword };