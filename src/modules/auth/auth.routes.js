import { Router } from "express";
import {
  registerWithEmailHandler,
  verifyEmailHandler,
  loginHandler,
  forgotPasswordHandler,
  resetPasswordHandler,
  googleAuthorizeHandler,
  googleCallbackHandler,
  getCurrentUserHandler,
  refreshTokenHandler,
} from "./auth.controller.js";
import { authRequired, loginRateLimiter } from "./auth.middleware.js";

const router = Router();

router.post("/register/email", registerWithEmailHandler);
router.get("/register/verify", verifyEmailHandler);
router.post("/login",loginRateLimiter, loginHandler);
router.post("/forgot-password", forgotPasswordHandler);
router.post("/reset-password", resetPasswordHandler);

// GET /oauth/:provider/authorize
// GET /oauth/:provider/callback
router.get("/oauth/google/authorize", googleAuthorizeHandler);
router.get("/oauth/google/callback", loginRateLimiter, googleCallbackHandler);

router.post("/refresh", refreshTokenHandler);

router.get("/me", authRequired, getCurrentUserHandler);

export default router;