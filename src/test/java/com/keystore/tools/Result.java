package com.keystore.tools;

public class Result<SUCCESS> {

    private final SUCCESS success;

    private final Throwable error;

    public Result(final SUCCESS success, final Throwable error) {
        this.success = success;
        this.error = error;
    }

    public SUCCESS getSuccessOrThrowException() {
        if (error != null) {
            throw new RuntimeException(error);
        }
        return success;
    }

    public Throwable getError() {
        return error;
    }
}
