package com.keystore.tools;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.function.Consumer;

public class HandlerImpl implements Handler {

    private final Consumer<Result<String>> afterMessageProcessed;

    public HandlerImpl(Consumer<Result<String>> afterMessageProcessed) {
        this.afterMessageProcessed = afterMessageProcessed;
    }

    @Override
    public void handle(final InputStream is, final OutputStream os) {
        try (
            final PrintWriter writer = new PrintWriter(os, true);
            final BufferedReader reader = new BufferedReader(new InputStreamReader(is))
        ) {
            final String line = reader.readLine();
            writer.println("OK");

            afterMessageProcessed.accept(new Result<>(line, null));
        } catch (final IOException ex) {
            afterMessageProcessed.accept(new Result<>(null, ex));
            throw new RuntimeException(ex);
        }
    }
}
