import { rateLimit } from "express-rate-limit";
import { verifyJWTAccessToken } from "./token.service.js";
import ApiError from "../../utils/ApiError.js";

const loginRateLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	limit: 10, // Limit each IP to 100 requests per `window` (here, per 15 minutes).
	standardHeaders: 'draft-8', // draft-6: `RateLimit-*` headers; draft-7 & draft-8: combined `RateLimit` header
	legacyHeaders: false, // Disable the `X-RateLimit-*` headers.
	ipv6Subnet: 56, // Set to 60 or 64 to be less aggressive, or 52 or 48 to be more aggressive
})

const authRequired = (req, res, next) => {
  try {
    const authHeader = req.headers["authorization"];

    if (!authHeader?.trim())
      throw new ApiError("Authorization header is required", 401);
    const tokenParts = authHeader.split(" ");

    if (tokenParts.length !== 2 || tokenParts[0] !== "Bearer") {
      return next(
        new ApiError(
          "Authorization header format should be: Bearer <token>",
          401
        )
      );
    }

    const token = tokenParts[1];

    const { sub, email, isEmailVerified } = verifyJWTAccessToken(token);
    req.user = {
      id: sub,
      email,
      isEmailVerified,
    };
    next();
  } catch (error) {
    throw new ApiError("Invalid or expired authentication token", 401);
  }
};

export { loginRateLimiter, authRequired };