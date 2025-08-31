import ApiError from "../../utils/ApiError.js";
import logger from "../../utils/logger.js";
import fs from "fs";

import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

class EmailService {
  constructor() {
    this.apiKey = process.env.EMAIL_CLIENT_API_KEY;
    this.baseURL = process.env.EMAIL_API_BASE_URL;
    this.fromEmail = process.env.FROM_EMAIL;
    this.fromName = process.env.FROM_NAME;

    // console.log(this.apiKey);
    // console.log(this.baseURL);
    // console.log(this.fromEmail);
    // console.log(this.fromName);
  }

  async sendEmail(emailData) {
    if (!this.apiKey || !this.baseURL || !this.fromEmail || !this.fromName)
      throw new Error("Invalid email service configuration");

    try {
      const response = await fetch(`${this.baseURL}/v1/email/send`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": this.apiKey,
        },
        body: JSON.stringify(emailData),
      });

      const responseData = await response.json();
      if (!response.ok) {
        logger.error("Email sending failed", {
          status: response.status,
          error: responseData,
          recipient: emailData.recipients?.[0]?.email,
        });
        throw new ApiError("Failed to send email, please try again later", 500);
      }

      if (!responseData.fail_count !== 0)
        throw new ApiError("Failed to send email, please try again later", 500);
      logger.info("Email sent successfully", {
        recipient: emailData.recipients?.[0]?.email,
        subject: emailData.content?.subject,
      });
      return { success: true, data: responseData };
    } catch (error) {
      if (error instanceof ApiError) throw error;
      logger.error("Email service error", {
        error: error.message,
        recipient: emailData.recipients?.[0]?.email,
      });
      throw new ApiError("Email service unavailable", 500);
    }
  }

  loadEmailTemplate(templateName, replacements = {}) {
    const templatePath = join(__dirname, "templates", templateName);
    let template = fs.readFileSync(templatePath, "utf-8");

    for (const key in replacements) {
      template = template.replace(`{{ ${key} }}`, replacements[key]);
    }

    return template;
  }

  async sendPasswordResetEmail(recipientUserName, recipientEmail, token) {
    recipientEmail = recipientEmail.trim();
    if (!recipientEmail) {
      throw new ApiError("Recipient email is required", 400);
    }
    if (!token) {
      throw new ApiError("Password reset token is required", 400);
    }

    const resetUrl = `${
      process.env.FRONTEND_URL
    }/reset-password?token=${encodeURIComponent(token)}`;

    const emailData = {
      from: {
        name: this.fromName,
        email: this.fromEmail,
      },
      recipients: [
        {
          name: recipientUserName,
          email: recipientEmail,
        },
      ],
      content: {
        subject: "Reset Your Password",
        html_body: this.loadEmailTemplate("password-reset.html", {
          recipientUserName,
          passwordResetLink: resetUrl,
        }),
      },
    };

    return await this.sendEmail(emailData);
  }

  async sendVerificationEmail(recipientUserName, recipientEmail, token) {
    recipientEmail = recipientEmail.trim();
    if (!recipientEmail) {
      throw new ApiError("Recipient email is required", 400);
    }
    if (!token) {
      throw new ApiError("Email verification token is required", 400);
    }

    const emailVerificationURL = `${
      process.env.FRONTEND_URL
    }/api/auth/register/verify?token=${encodeURIComponent(token)}`;

    const emailData = {
      from: {
        name: this.fromName,
        email: this.fromEmail,
      },
      recipients: [
        {
          name: recipientUserName,
          email: recipientEmail,
        },
      ],
      content: {
        subject: "Verify Your Email",
        html_body: this.loadEmailTemplate("verification-email.html", {
          recipientUserName,
          emailVerificationLink: emailVerificationURL,
        }),
      },
    };

    return await this.sendEmail(emailData);
  }
}

export default new EmailService();
