// src/middleware/errorHandler.js
import { error } from '/auth-service/src/utils/response.js';
import ApiError from '../utils/ApiError.js';

export const errorHandler = (err, req, res, next) => {
  if (err instanceof ApiError) {
    return error(res, err.message, err.status, err.errors);
  }

  console.error(err); // log unexpected errors
  return error(res, "Internal server error", 500, []);
};