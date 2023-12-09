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
    public static Map<String, Object> getPublicId(String credentials, HikariDataSource dataSource, PasswordEncoder passwordEncoder)  {
        return loadUserByUsername(credentials, dataSource, passwordEncoder);
    }

    private static Map<String, Object> loadUserByUsername(String credentials,
                                                          HikariDataSource dataSource,
                                                          PasswordEncoder passwordEncoder)  {
        return UserPasswordAuthenticator.authenticate(credentials, passwordEncoder, dataSource);

    }
}
