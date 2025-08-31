import ApiError from "../../utils/ApiError.js";
import {
  registerWithEmail,
  login,
  verifyEmail,
  forgotPassword,
  resetPassword,
  googleAuthorize,
  googleCallback,
  rotateRefreshToken,
  getCurrentUser,
} from "./auth.service.js";
import { success } from "../../utils/response.js";

const registerWithEmailHandler = async (req, res, next) => {
  const { email, password, firstName, lastName } = req.body;

  const errors = [];
  try {
    const normalizedEmail = email?.trim().toLowerCase();
    const normalizedFirstName = firstName?.trim();
    const normalizedLastName = lastName?.trim();
    if (!normalizedEmail) errors.push({ message: "Email is required" });
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      errors.push({ message: "Invalid email format" });
    }

    if (!password) errors.push({ message: "Password is required" });
    else if (password.length < 8) {
      errors.push({ message: "Password must be at least 8 characters" });
    }

    if (!normalizedFirstName)
      errors.push({ message: "First name is required" });

    if (errors.length > 0) throw new ApiError("Validation Error", 400, errors);
    const tokens = await registerWithEmail(
      normalizedEmail,
      password,
      normalizedFirstName,
      normalizedLastName
    );
    success(
      res,
      { ...tokens },
      "Registration successful. A verification email has been sent to your inbox.",
      201
    );
  } catch (error) {
    next(error);
  }
};

const verifyEmailHandler = async (req, res, next) => {
  try {
    const { token } = req.query;
    const normalizedToken = token?.trim();
    if (!normalizedToken)
      throw new ApiError("Verification token is required", 400);

    const response = await verifyEmail(normalizedToken);
    if (response.alreadyVerified)
      return success(res, {}, "Email is already verified", 200);
    success(res, {}, "Email verified successfully", 200);
  } catch (error) {
    next(error);
  }
};

const loginHandler = async (req, res, next) => {
  const { email, password } = req.body;

  const errors = [];
  const normalizedEmail = email?.trim().toLowerCase();
  try {
    if (!normalizedEmail) errors.push({ message: "Email is required" });
    if (!password) errors.push({ message: "Password is required" });

    if (errors.length > 0) throw new ApiError("Validation Error", 400, errors);

    const data = await login(normalizedEmail, password);

    if (!data) {
      throw new ApiError("Invalid email or password", 401);
    }

    success(res, { ...data }, "Login successful", 200);
  } catch (error) {
    next(error);
  }
};

const forgotPasswordHandler = async (req, res, next) => {
  try {
    const { email } = req.body;
    const normalizedEmail = email?.trim().toLowerCase();
    if (!normalizedEmail) throw new ApiError("Email is required", 400);
    await forgotPassword(normalizedEmail);
    success(
      res,
      {},
      "If an account with this email exists, a password reset link has been sent.",
      200
    );
  } catch (error) {
    next(error);
  }
};

const resetPasswordHandler = async (req, res, next) => {
  try {
    const { token, password } = req.body;
    const normalizedToken = token?.trim();
    if (!normalizedToken)
      throw new ApiError("Password reset token is required", 400);
    if (!password) throw new ApiError("Password is required", 400);
    else if (password.length < 8)
      throw new ApiError("Password must be at least 8 characters", 400);

    await resetPassword(normalizedToken, password);
    success(
      res,
      {},
      "Password has been reset successfully. Please log in with your new password",
      200
    );
  } catch (error) {
    next(error);
  }
};

const googleAuthorizeHandler = async (req, res, next) => {
  try {
    const url = await googleAuthorize();
    // Prod
    // success(res, { url }, "Google login URL generated successfully", 200);
  
    // Dev
    res.status(302).redirect(url);
  } catch (error) {
    next(error);
  }
};

const googleCallbackHandler = async (req, res, next) => {
  try {
    const normalizedCode = req.query.code?.trim();
    const normalizedState = req.query.state?.trim();
    if (!normalizedCode) throw new ApiError("Code is required", 400);
    if (!normalizedState) throw new ApiError("State token is required", 400);
    const tokens = await googleCallback(normalizedCode, normalizedState);
    success(res, { ...tokens }, "Google login successful", 200);
  } catch (error) {
    next(error);
  }
};

const refreshTokenHandler = async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    const normalizedRefreshToken = refreshToken?.trim();
    if (!normalizedRefreshToken)
      throw new ApiError("Refresh token is required", 400);
    const token = await rotateRefreshToken(normalizedRefreshToken);
    success(res, { ...token }, "Tokens refreshed successfully", 200);
  } catch (error) {
    next(error);
  }
};

const getCurrentUserHandler = async (req, res, next) => {
  try {
    if (!req.user) throw new ApiError("User not found", 404);
    const user = await getCurrentUser(req.user.id);
    if (!user) throw new ApiError("User not found", 404);
    success(res, user, "User fetched successfully", 200);
  } catch (error) {
    next(error);
  }
};

export {
  registerWithEmailHandler,
  loginHandler,
  verifyEmailHandler,
  forgotPasswordHandler,
  resetPasswordHandler,
  googleAuthorizeHandler,
  googleCallbackHandler,
  refreshTokenHandler,
  getCurrentUserHandler,
};
