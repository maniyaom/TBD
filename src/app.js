// import { configDotenv } from "dotenv";
// configDotenv();
import "dotenv/config";

import express from "express";
import authRouter from "./modules/auth/index.js";
import { errorHandler } from "./middleware/errorHandler.js";

const app = express();

app.use(express.json());

app.use("/api/auth", authRouter);

app.use(errorHandler);

export default app;
