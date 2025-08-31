class ApiError extends Error {
    constructor(message="Something went wrong", status=500, errors = []) {
        super();
        this.message = message;
        this.status = status;
        this.errors = errors;
    }
}

export default ApiError;