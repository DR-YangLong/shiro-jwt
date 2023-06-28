/*
 * Copyright 2023 YangLong
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package io.github.yanglong.shiro.jwt;

import com.nimbusds.jose.jwk.Curve;
import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 用途描述：配置JWT相关信息
 *
 * @author YangLong
 * @version V1.0
 * @since 2023/6/23
 */
@Data
@Component("jwtProperties")
@Order(value = Ordered.HIGHEST_PRECEDENCE)
public class JwtProperties {
    
    /**
     * RSA/ECDSA私钥 建议密钥长度最低为2048，算法和最低密钥长度对应为RSA256=256*4=1024，RSA512=4*512=2048
     */
    @Value("${shiro.jwt.privateKey}")
    private String privateKey;
    
    /**
     * RSA/ECDSA公钥
     */
    @Value("${shiro.jwt.publicKey}")
    private String publicKey;
    
    /**
     * ECDSA模式:P_256,P_384,P_521
     * <p>
     * ES256 - EC P-256 DSA with SHA-256
     * <p>
     * ES384 - EC P-384 DSA with SHA-384
     * <p>
     * ES512 - EC P-521 DSA with SHA-512
     */
    @Value("${shiro.jwt.dsaCurve}")
    private Curve dsaCurve;
    
    /**
     * HMAC密钥
     */
    @Value("${shiro.jwt.hacSecretKey}")
    private String hacSecretKey;
    
    /**
     * TOKEN有效时长
     */
    @Value("${shiro.jwt.expirationTime}")
    private Duration expirationTime;
    
    /**
     * 签发者名称
     */
    @Value("${shiro.jwt.issuer}")
    private String issuer;
    
    /**
     * token在请求头中的key
     */
    @Value("${shiro.jwt.header:'X-CND-NODE'}")
    private String tokenHeader;
    
    /**
     * JWT前缀，完整header:bearer token
     */
    @Value("${shiro.jwt.bearer:Must}")
    private String tokenBearer;
    
    /**
     * shiro definitions
     */
    @Value("#{${shiro.definitions}}")
    private Map<String, String> definitions = new LinkedHashMap<>();
    
    /**
     * shiro扩展filters
     */
    @Value("#{${shiro.filters}}")
    private Map<String, String> filters = new LinkedHashMap<>();
    
    /**
     * shiro未登录跳转的登录地址，会重定向到此地址进行登录
     */
    @Value("${shiro.loginUrl}")
    private String loginUrl;
    
    /**
     * 权限受限地址
     */
    @Value("${shiro.unauthorizedUrl}")
    private String unauthorizedUrl;
}
