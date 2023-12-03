package com.jade.platform.util;

import java.util.Base64;

/**
 * @Author: Josiah Adetayo
 * @Email: josleke@gmail.com, josiah.adetayo@meld-tech.com
 * @Date: 12/1/23
 */
public class MessageEncoding {
    public static String base64Decoding(String encodedString) {
        if(encodedString == null || encodedString.isEmpty()) return "";
        return new String(Base64.getDecoder().decode(encodedString));
    }
}
