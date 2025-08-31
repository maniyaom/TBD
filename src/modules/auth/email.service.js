import ApiError from "../../utils/ApiError.js";

async function sendVerificationEmail(recipientEmail, token) {
  if (!recipientEmail) throw new ApiError("Recipient email is required", 400);
  if (!token) throw new ApiError("Verification token is required", 400);

  const emailContent = {
    from: {
      name: "Auth Service",
      email: "no-reply@krishilink.ommaniya.site",
    },
    recipients: [
      {
        name: "Test User",
        email: recipientEmail,
      },
    ],
    content: {
      subject: "Auth Service Verification email",
      html_body: `
            <body>
                <h1>Auth Service Verification email</h1>
                <p>Click the link below to verify your email address</p>
                <a href=${process.env.BACKEND_URL}/auth/verify?token=${encodeURIComponent(token)}>Verify email</a>
            </body>
            `,
    },
  };

  try {
    const response = await fetch("https://api.ahasend.com/v1/email/send", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Api-Key": process.env.EMAIL_CLIENT_API_KEY,
      },
      body: JSON.stringify(emailContent),
    });
    console.log(response);

    if (!response.ok) {
      console.log(response);
      throw new ApiError("Failed to send verification email", 500);
    }
  } catch (error) {
    console.log(response);
    throw new ApiError("Failed to send verification email", 500);
  }
}

async function sendPasswordResetEmail(recipientEmail, token) {
  if (!recipientEmail) throw new ApiError("Recipient email is required", 400);
  if (!token) throw new ApiError("Password reset token is required", 400);

  const emailContent = {
    from: {
      name: "Auth Service",
      email: "no-reply@krishilink.ommaniya.site",
    },
    recipients: [
      {
        name: "Test User",
        email: recipientEmail,
      },
    ],
    content: {
      subject: "Auth Service Password reset email",
      html_body: `
            <body>
                <h1>Auth Service Password reset email</h1>
                <p>Click the link below to reset your password</p>
                <a href=${process.env.BACKEND_URL}/api/auth/reset-password/verify?token=${encodeURIComponent(token)}>Reset password</a>
            </body>
            `,
    },
  };

  try {
    const response = await fetch("https://api.ahasend.com/v1/email/send", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Api-Key": process.env.EMAIL_CLIENT_API_KEY,
      },
      body: JSON.stringify(emailContent),
    });
    console.log(response);

    if (!response.ok) {
      console.log(response);
      throw new ApiError("Failed to send password reset email", 500);
    }
  } catch (error) {
    console.log(response);
    throw new ApiError("Failed to send password reset email", 500);
  }
}

async function validateEmail(email) {
  const [localPart, domain] = email.split("@");
  if (!localPart || !domain) {
    throw new ApiError("Invalid email address", 400);
  }
  if (localPart.includes("+")) {
    throw new ApiError("Invalid email address", 400);
  }
  try {
    const response = await fetch(
      `https://api.mails.so/v1/validate?email=${email}`,
      {
        method: "GET",
        headers: {
          "x-mails-api-key": process.env.EMAIL_VERIFIER_API_KEY,
        },
      }
    );
    if (!response.ok) {
      throw new ApiError("Email validation service failed", 500);
    }
    const data = await response.json();
    console.log(data);
    if (data.data.result !== "deliverable")
      throw new ApiError("Invalid email address", 400);
    return true;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError("Failed to validate email", 500);
  }
}

export { sendVerificationEmail, validateEmail, sendPasswordResetEmail };

/*

Sample email response:

Response {
  status: 201,
  statusText: 'Created',
  headers: Headers {
    date: 'Tue, 26 Aug 2025 10:52:35 GMT',
    'content-type': 'application/json; charset=UTF-8',
    'content-length': '69',
    connection: 'keep-alive',
    server: 'cloudflare',
    nel: '{"report_to":"cf-nel","success_fraction":0.0,"max_age":604800}',
    'x-request-id': 'RkYjLVveCdexbWitIHtWNxDPALOFlyst',
    'x-frame-options': 'SAMEORIGIN',
    'cf-cache-status': 'DYNAMIC',
    'report-to': '{"group":"cf-nel","max_age":604800,"endpoints":[{"url":"https://a.nel.cloudflare.com/report/v4?s=p5F7vSv375eNPk%2F7KKN0tI5ZPBZ7jp5o3AxyXmdve7747GNN3ViS0YeQFIQ0rn0FeB55fyqVIrHYVB95qcblITfbxbwkXnsFCeay%2FxHg6mqv26vs5R0bmBxarA%3D%3D"}]}',
    'cf-ray': '9752c7cc4ce9cdd6-SIN',
    'alt-svc': 'h3=":443"; ma=86400'
  },
  body: ReadableStream { locked: false, state: 'readable', supportsBYOB: true },
  bodyUsed: false,
  ok: true,
  redirected: false,
  type: 'basic',
  url: 'https://api.ahasend.com/v1/email/send'
}

*/
