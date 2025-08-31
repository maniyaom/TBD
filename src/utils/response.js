const success = (res, data = {}, message = "success", status=200) => {
    return res.status(status).json({
        status: "success",
        message,
        data,
    });
}

const error = (res, message = "Something went wrong", status=500, errors = []) => {
    return res.status(status).json({
        status: "error",
        message,
        errors,
    });
}

export { success, error };