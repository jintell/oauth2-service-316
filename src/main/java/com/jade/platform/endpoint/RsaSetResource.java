package com.jade.platform.endpoint;

import com.nimbusds.jose.jwk.JWKSet;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * @Author: Josiah Adetayo
 * @Email: josleke@gmail.com, josiah.adetayo@meld-tech.com
 * @Date: 12/1/23
 */
@RestController
@RequiredArgsConstructor
public class RsaSetResource {
    private final JWKSet jwkSet;

    @GetMapping("/.well-known/authorization-server/jwks.json")
    public Map<String, Object> keys() {
        return jwkSet.toJSONObject();
    }
}
