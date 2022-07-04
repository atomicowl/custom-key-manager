package com.keystore.tools;

import java.io.InputStream;
import java.io.OutputStream;

public interface Handler {

    void handle(InputStream is, OutputStream os);

}
