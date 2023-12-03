package com.jade.platform.util;

import com.zaxxer.hikari.HikariDataSource;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Map;
/**
 * @Author: Josiah Adetayo
 * @Email: josleke@gmail.com, josiah.adetayo@meld-tech.com
 * @Date: 12/1/23
 */
public class CustomTokenAttribute {
    private CustomTokenAttribute() {}
    public static String getPublicId(String credentials, HikariDataSource dataSource, PasswordEncoder passwordEncoder)  {
        return String.format("%s",
                loadUserByUsername(credentials, dataSource, passwordEncoder).get("public_id"));
    }

    private static Map<String, Object> loadUserByUsername(String credentials,
                                                          HikariDataSource dataSource,
                                                          PasswordEncoder passwordEncoder)  {
        return UserPasswordAuthenticator.authenticate(credentials, passwordEncoder, dataSource);

    }
}
