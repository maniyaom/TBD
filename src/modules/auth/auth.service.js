import prisma from "/auth-service/src/config/prisma.js";
import ApiError from "/auth-service/src/utils/ApiError.js";
import { hashPassword, comparePassword } from "./password.utils.js";
import {
  generateJWTRefreshToken,
  verifyJWTRefreshToken,
} from "./token.service.js";
import {
  validateEmail,
} from "./email.service.js";
import { ActionType, AuthProviderType } from "./constants.js";
import { generateJWTAccessToken } from "./token.service.js";
import { hashToken } from "../../utils/hashToken.js";
import { google } from "googleapis";
import logger from "../../utils/logger.js";
import { randomBytes } from "crypto";
import EmailService from "../../services/email/email.service.js";

const registerWithEmail = async (email, password, firstName, lastName) => {
  try {
    await validateEmail(email);
    const hashedPassword = await hashPassword(password);
    const token = randomBytes(64).toString("hex");
    const expiresAt = new Date(
      Date.now() + Number.parseInt(process.env.VERIFICATION_TOKEN_EXPIRY_TIME)
    );

    const tokens = await prisma.$transaction(async (tx) => {
      const user = await tx.user.create({
        data: {
          firstName,
          lastName: lastName || null,
          email,
          authProviders: {
            create: {
              authProviderType: AuthProviderType.EMAIL_PASSWORD,
              password: hashedPassword,
            },
          },
        },
      });

      await tx.ActionToken.create({
        data: {
          token,
          userId: user.id,
          type: ActionType.EMAIL_VERIFICATION,
          expiresAt,
        },
      });

      const accessToken = generateJWTAccessToken({
        id: user.id,
        email: user.email,
        isEmailVerified: false,
      });

      const refreshToken = generateJWTRefreshToken(user.id);

      await tx.RefreshToken.create({
        data: {
          token: hashToken(refreshToken),
          userId: user.id,
        },
      });

      return { accessToken, refreshToken };
    });

    console.log("Use this token to verify on temporary basis: ", token);

    const recipientUserName = user.lastName ? `${user.firstName} ${user.lastName}` : user.firstName;
    await EmailService.sendVerificationEmail(recipientUserName, email, token);
    return tokens;
  } catch (error) {
    if (error.code === "P2002") {
      const target = error.meta?.target;
      if (target?.includes("email")) {
        throw new ApiError("Email already registered", 409);
      }
    }

    // Handle other Prisma errors
    if (error.code?.startsWith("P")) {
      logger.error("Database error during registration", {
        error: error.code,
        email,
      });
      throw new ApiError("Registration failed", 500);
    }

    throw error;
  }
};

const verifyEmail = async (token) => {
  try {
    const actionToken = await prisma.ActionToken.findUnique({
      where: {
        token,
      },
      include: {
        user: true,
      },
    });

    if (
      !actionToken ||
      !actionToken.user ||
      actionToken.type !== ActionType.EMAIL_VERIFICATION
    )
      throw new ApiError("Invalid verification link", 404);

    if (actionToken.usedAt)
      throw new ApiError("Verification link has already been used", 410);

    if (actionToken.expiresAt < new Date())
      throw new ApiError(
        "Verification link has expired. Please request a new verification email.",
        410
      );

    if (actionToken.user.isEmailVerified) return { alreadyVerified: true };

    await prisma.$transaction([
      prisma.user.update({
        where: { id: actionToken.userId },
        data: { isEmailVerified: true },
      }),

      prisma.ActionToken.update({
        where: { id: actionToken.id },
        data: { usedAt: new Date() },
      }),
    ]);
    return { verified: true };
  } catch (error) {
    throw error;
  }
};

const login = async (email, password) => {
  try {
    const user = await prisma.user.findUnique({
      where: {
        email,
      },
      select: {
        id: true,
        email: true,
        isEmailVerified: true,
        authProviders: {
          where: {
            authProviderType: AuthProviderType.EMAIL_PASSWORD,
          },
          select: {
            password: true,
          },
        },
      },
    });

    // console.log("AUTH SERVICE: ", user);

    if (!user) {
      throw new ApiError("Invalid email or password", 401);
    }

    if (!user.authProviders[0]?.password)
      throw new ApiError(
        "Invalid login credentials. Please try signing in with Google if you registered using Google.",
        400
      );
    const isPasswordValid = await comparePassword(
      password,
      user.authProviders[0].password
    );
    if (!isPasswordValid) {
      throw new ApiError("Invalid email or password", 401);
    }

    const JWT_ACCESS_TOKEN = generateJWTAccessToken({
      id: user.id,
      email: user.email,
      isEmailVerified: user.isEmailVerified,
    });
    const JWT_REFRESH_TOKEN = generateJWTRefreshToken(user.id);
    const hashedToken = hashToken(JWT_REFRESH_TOKEN);
    await prisma.RefreshToken.create({
      data: {
        token: hashedToken,
        userId: user.id,
      },
    });
    return { JWT_ACCESS_TOKEN, JWT_REFRESH_TOKEN };
  } catch (error) {
    throw error;
  }
};

const forgotPassword = async (email) => {
  try {
    const user = await prisma.user.findUnique({
      where: {
        email,
        authProviders: {
          some: {
            authProviderType: AuthProviderType.EMAIL_PASSWORD,
          },
        },
      },
    });

    console.log(user);
    if (!user) {
      logger.warn("Password reset attempted for non-existent email", { email });
      return {
        processed: true,
        message: "Password reset attempted for non-existent email",
      };
    }

    const token = randomBytes(64).toString("hex");
    const expiresAt = new Date(
      Date.now() + Number.parseInt(process.env.PASSWORD_RESET_TOKEN_EXPIRY_TIME)
    );

    await prisma.ActionToken.create({
      data: {
        token,
        userId: user.id,
        type: ActionType.PASSWORD_RESET,
        expiresAt,
      },
    });

    const recipientUserName = user.lastName ? `${user.firstName} ${user.lastName}` : user.firstName;
    console.log("Use this token to reset password: ", token);
    await EmailService.sendPasswordResetEmail(recipientUserName, email, token);
    return {
      processed: true,
      message: "A password reset link has been sent to the given email.",
    };
  } catch (error) {
    throw error;
  }
};

const resetPassword = async (token, password) => {
  try {
    const actionToken = await prisma.ActionToken.findUnique({
      where: {
        token,
      },
      include: {
        user: true,
      },
    });

    if (!actionToken)
      throw new ApiError("Invalid or expired password reset link", 400);

    if (actionToken.type !== ActionType.PASSWORD_RESET || !actionToken.user)
      throw new ApiError("Invalid password reset link", 400);

    if (actionToken.usedAt)
      throw new ApiError("Password reset link has already been used", 400);

    if (actionToken.expiresAt < new Date())
      throw new ApiError("Password reset link has expired", 400);

    const hashedPassword = await hashPassword(password);

    await prisma.$transaction([
      prisma.AuthProvider.update({
        where: {
          userId_authProviderType: {
            userId: actionToken.user.id,
            authProviderType: AuthProviderType.EMAIL_PASSWORD,
          },
        },
        data: {
          password: hashedPassword,
        },
      }),
      prisma.ActionToken.update({
        where: {
          id: actionToken.id,
        },
        data: {
          usedAt: new Date(),
        },
      }),
      prisma.RefreshToken.updateMany({
        where: {
          userId: actionToken.user.id,
        },
        data: {
          revoked: true,
          revokedAt: new Date(),
        },
      }),
    ]);

    logger.info("Password reset completed", {
      userId: actionToken.userId,
      email: actionToken.user.email,
    });

    return {
      success: true,
      userId: actionToken.userId,
    };
  } catch (error) {
    throw error;
  }
};

const googleAuthorize = async () => {
  if (
    !process.env.GOOGLE_CLIENT_ID ||
    !process.env.GOOGLE_CLIENT_SECRET ||
    !process.env.GOOGLE_REDIRECT_URI
  ) {
    throw new Error("Missing Google OAuth configuration");
  }
  const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
  );

  const scopes = [
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "openid",
  ];

  // Uncomment for prod
  const state = randomBytes(32).toString("hex");

  const new_state_token = await prisma.OAuthStateToken.create({
    data: {
      token: state,
    },
  });

  console.log(
    "GOOGLE_AUTH_STATE_TOKEN: ",
    new_state_token,
    "\nAt time: ",
    new Date().toString()
  );

  const url = oauth2Client.generateAuthUrl({
    scope: scopes,
    include_granted_scopes: true,
    state: state,
    prompt: "consent",
    response_type: "code",
  });
  return url;
};

const googleCallback = async (code, state) => {
  try {
    if (
      !process.env.GOOGLE_CLIENT_ID ||
      !process.env.GOOGLE_CLIENT_SECRET ||
      !process.env.GOOGLE_REDIRECT_URI
    )
      throw new Error("Missing Google OAuth configuration");

    const oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      process.env.GOOGLE_REDIRECT_URI
    );
    const { tokens } = await oauth2Client.getToken(code);

    if (!tokens.id_token) {
      throw new ApiError("Invalid response from Google", 400);
    }

    const ticket = await oauth2Client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    // console.log("User payload from ID token:", payload);

    if (!payload.email || !payload.sub) {
      throw new ApiError("Incomplete user information from Google", 400);
    }

    const scopes = tokens.scope?.split(" ");
    if (!scopes || scopes.length < 3)
      throw new ApiError("Insufficient Google permissions", 400);
    if (
      !scopes.includes("https://www.googleapis.com/auth/userinfo.email") ||
      !scopes.includes("https://www.googleapis.com/auth/userinfo.profile") ||
      !scopes.includes("openid")
    ) {
      throw new ApiError("Invalid Google credentials", 400);
    }

    const deletedStateToken = await prisma.OAuthStateToken.delete({
      where: {
        token: state,
      },
    });

    const stateTokenExpiryTime =
      deletedStateToken.createdAt.getTime() +
      Number.parseInt(process.env.OAUTH_STATE_TOKEN_EXPIRY_TIME);

    console.log("State token expiry time: ", stateTokenExpiryTime);
    console.log("Current time: ", Date.now());

    if (stateTokenExpiryTime < Date.now())
      throw new ApiError("State token has expired", 400);
    console.log(deletedStateToken);

    const user = await prisma.$transaction(async (tx) => {
      let existingUser = await tx.user.findFirst({
        where: {
          email: payload.email,
        },
        select: {
          id: true,
          email: true,
          isEmailVerified: true,
          authProviders: {
            where: {
              authProviderType: AuthProviderType.GOOGLE,
              authProviderUserId: payload.sub,
            },
          },
        },
      });

      if (!existingUser) {
        return await tx.user.create({
          data: {
            firstName: payload.given_name,
            lastName: payload.family_name || null,
            email: payload.email,
            profileImage: payload.picture,
            isEmailVerified: payload.email_verified,
            authProviders: {
              create: {
                authProviderType: AuthProviderType.GOOGLE,
                authProviderUserId: payload.sub,
              },
            },
          },
          select: {
            id: true,
            email: true,
            isEmailVerified: true,
          },
        });
      } else if (existingUser.authProviders.length === 0) {
        return await tx.user.update({
          where: {
            id: existingUser.id,
          },
          data: {
            isEmailVerified: payload.email_verified,
            authProviders: {
              create: {
                authProviderType: AuthProviderType.GOOGLE,
                authProviderUserId: payload.sub,
              },
            },
          },
          select: {
            id: true,
            email: true,
            isEmailVerified: true,
          },
        });
      } else {
        return await tx.user.update({
          where: {
            id: existingUser.id,
          },
          data: {
            firstName: payload.given_name,
            lastName: payload.family_name || null,
            profileImage: payload.picture,
            isEmailVerified: payload.email_verified,
          },
          select: {
            id: true,
            email: true,
            isEmailVerified: true,
          },
        });
      }
    });

    const accessToken = generateJWTAccessToken({
      id: user.id,
      email: user.email,
      isEmailVerified: user.isEmailVerified,
    });

    const refreshToken = generateJWTRefreshToken({
      id: user.id,
    });

    await prisma.RefreshToken.create({
      data: {
        token: hashToken(refreshToken),
        userId: user.id,
      },
    });

    console.log(accessToken);
    console.log(refreshToken);
    console.log(user);

    return {
      accessToken,
      refreshToken,
    };
  } catch (error) {
    console.error("Google OAuth callback error:", error);

    if (
      error.code === "P2025" &&
      error?.meta?.modelName === "OAuthStateToken" &&
      error?.meta?.cause === "No record was found for a delete."
    )
      throw new ApiError("State mismatch. Possible CSRF attack", 401);

    // Handle specific Google API errors
    if (error.message?.includes("invalid_grant"))
      throw new ApiError("Authorization code expired or invalid", 400);
    if (error.message === "invalid_client")
      throw new ApiError("OAuth configuration error", 500);
    if (error.message?.includes("Token used too late"))
      throw new ApiError("Authorization code expired", 400);

    if (error instanceof ApiError) throw error;

    throw new ApiError("Google authentication failed", 500);
  }
};

const rotateRefreshToken = async (refreshToken) => {
  try {
    verifyJWTRefreshToken(refreshToken);
    const hashedRefreshToken = hashToken(refreshToken);
    const data = await prisma.RefreshToken.findUnique({
      where: {
        token: hashedRefreshToken,
      },
      select: {
        revoked: true,
        user: {
          select: {
            id: true,
            email: true,
            isEmailVerified: true,
          },
        },
      },
    });

    if (!data) throw new ApiError("Failed to verify token: invalid token", 401);

    if (data.revoked)
      throw new ApiError("Failed to verify token: token revoked", 401);

    const newRefreshToken = generateJWTRefreshToken(data.user.id);
    const newAccessToken = generateJWTAccessToken({
      id: data.user.id,
      email: data.user.email,
      isEmailVerified: data.user.isEmailVerified,
    });

    await prisma.$transaction([
      prisma.RefreshToken.update({
        where: {
          token: hashedRefreshToken,
        },
        data: {
          revoked: true,
          revokedAt: new Date(),
        },
      }),
      prisma.RefreshToken.create({
        data: {
          token: hashToken(newRefreshToken),
          userId: data.user?.id,
        },
      }),
    ]);

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    };
  } catch (error) {
    throw error;
  }
};

const getCurrentUser = async (userId) => {
  try {
    const user = await prisma.user.findUnique({
      where: {
        id: userId,
      },
    });

    if (!user) throw new ApiError("User not found", 404);

    return user;
  } catch (error) {
    throw error;
  }
};

export {
  registerWithEmail,
  login,
  verifyEmail,
  forgotPassword,
  resetPassword,
  googleAuthorize,
  googleCallback,
  rotateRefreshToken,
  getCurrentUser,
};
