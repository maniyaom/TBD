import jwt from "jsonwebtoken";
import ApiError from "../../utils/ApiError.js";
import { randomBytes } from "crypto";

function generateJWTAccessToken(user) {
  if (!user)
    throw new ApiError("Failed to generate token: missing user data.", 500);
  const payload = {
    sub: user.id,
    email: user.email,
    isEmailVerified: user.isEmailVerified,
    iat: Number.parseInt(Date.now() / 1000),
    exp:
      Number.parseInt(Date.now() / 1000) +
      Number.parseInt(process.env.JWT_ACCESS_TOKEN_EXPIRY_TIME),
  };
  return jwt.sign(payload, process.env.JWT_ACCESS_TOKEN_SECRET, {
    algorithm: process.env.JWT_ALGORITHM,
  });
}

function generateJWTRefreshToken(id) {
  if (!id) {
    throw new ApiError("Failed to generate token: missing user id.", 500);
  }
  const payload = {
    sub: id,
    type: "refresh",
    iat: Number.parseInt(Date.now() / 1000),
    exp:
      Number.parseInt(Date.now() / 1000) +
      Number.parseInt(process.env.JWT_REFRESH_TOKEN_EXPIRY_TIME),
  };

  return jwt.sign(payload, process.env.JWT_REFRESH_TOKEN_SECRET, {
    algorithm: process.env.JWT_ALGORITHM,
  });
}

function verifyJWTAccessToken(token) {
  if (!token?.trim()) {
    throw new ApiError("Failed to verify token: missing token.", 401);
  }
  try {
    const data = jwt.verify(token, process.env.JWT_ACCESS_TOKEN_SECRET);
    return data;
  } catch (error) {
    throw new ApiError("Failed to verify token: invalid token.", 401);
  }
}

function verifyJWTRefreshToken(token) {
  if (!token?.trim()) {
    throw new ApiError("Failed to verify token: missing token.", 401);
  }
  try {
    const data = jwt.verify(token, process.env.JWT_REFRESH_TOKEN_SECRET);
    return data;
  } catch (error) {
    throw new ApiError("Failed to verify token: invalid token.", 401);
  }
}

export {
  generateJWTAccessToken,
  verifyJWTAccessToken,
  generateJWTRefreshToken,
  verifyJWTRefreshToken,
};
