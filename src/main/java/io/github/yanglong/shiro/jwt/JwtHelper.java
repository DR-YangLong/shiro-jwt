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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.apache.shiro.util.CollectionUtils;
import org.springframework.lang.NonNull;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.Map;

/**
 * 用途描述：JWT签发，解码，验签
 *
 * @author YangLong
 * @version V1.0
 * @since 2023/6/23
 */
@Slf4j
public class JwtHelper {
    
    /**
     * 创建JWT
     *
     * @param jwsAlgorithm   算法
     * @param privateKey     私钥，可选
     * @param hacSecret      hmac模式密钥，可选
     * @param esCurve        ECDSA算法模式，需要和privateKey匹配
     * @param issuer         签发者
     * @param subject        主题
     * @param expirationTime 有效期
     * @param tokenId        凭证ID
     * @param customClaims   自定义属性
     * @return SignedJWT
     * @throws NoSuchAlgorithmException 当算法不是HMAC,RSA,ECDSA时抛出
     * @throws JOSEException            参数错误时抛出
     * @throws InvalidKeySpecException  密钥格式不正确时抛出
     */
    public static String signJwtToken(@NonNull JWSAlgorithm jwsAlgorithm, String privateKey, String hacSecret,
            Curve esCurve, String issuer, String subject, long expirationTime, String tokenId,
            Map<String, Object> customClaims) throws NoSuchAlgorithmException, JOSEException, InvalidKeySpecException {
        return signWithAlgorithm(jwsAlgorithm, privateKey, hacSecret, esCurve, issuer, subject, expirationTime, tokenId,
                customClaims).serialize();
    }
    
    /**
     * 创建JWT
     *
     * @param jwsAlgorithm   算法
     * @param privateKey     私钥，可选
     * @param hacSecret      hmac模式密钥，可选
     * @param esCurve        ECDSA算法模式，需要和privateKey匹配
     * @param issuer         签发者
     * @param subject        主题
     * @param expirationTime 有效期
     * @param tokenId        凭证ID
     * @param customClaims   自定义属性
     * @return SignedJWT
     * @throws NoSuchAlgorithmException 当算法不是HMAC,RSA,ECDSA时抛出
     * @throws JOSEException            参数错误时抛出
     * @throws InvalidKeySpecException  密钥格式不正确时抛出
     */
    public static SignedJWT signWithAlgorithm(@NonNull JWSAlgorithm jwsAlgorithm, String privateKey, String hacSecret,
            Curve esCurve, String issuer, String subject, long expirationTime, String tokenId,
            Map<String, Object> customClaims) throws NoSuchAlgorithmException, JOSEException, InvalidKeySpecException {
        JWSSigner signer = jwsSigner(jwsAlgorithm, privateKey, hacSecret, esCurve);
        JWSHeader header = header(jwsAlgorithm);
        JWTClaimsSet claims = claimsSet(issuer, subject, expirationTime, tokenId, customClaims);
        return sign(header, claims, signer);
    }
    
    /**
     * 签发JWT
     *
     * @param jwsHeader jwt头
     * @param claims    jwt payload
     * @param signer    签名器
     * @return SignedJWT
     */
    protected static SignedJWT sign(JWSHeader jwsHeader, JWTClaimsSet claims, JWSSigner signer) throws JOSEException {
        SignedJWT signedJWT = new SignedJWT(jwsHeader, claims);
        signedJWT.sign(signer);
        return signedJWT;
    }
    
    /**
     * 创建签名器
     *
     * @param jwsAlgorithm 算法
     * @param privateKey   私钥，可选
     * @param hacSecret    公钥，可选
     * @param esCurve      ECDSA算法模式，需要和privateKey匹配
     * @return JWT签名器
     * @throws NoSuchAlgorithmException 当算法不是HMAC,RSA,ECDSA时抛出
     * @throws JOSEException            参数错误时抛出
     * @throws InvalidKeySpecException  密钥格式不正确时抛出
     */
    protected static JWSSigner jwsSigner(JWSAlgorithm jwsAlgorithm, String privateKey, String hacSecret, Curve esCurve)
            throws NoSuchAlgorithmException, JOSEException, InvalidKeySpecException {
        JWSSigner signer = null;
        String algorithm = jwsAlgorithm.getName();
        if (algorithm.contains("HS")) {
            //HMAC
            signer = new MACSigner(hacSecret);
        }
        if (algorithm.contains("RS")) {
            //RSA
            PrivateKey key = privateKeyFromString(privateKey, "RSA");
            signer = new RSASSASigner(key);
        }
        if (algorithm.contains("ES")) {
            //ECDSA
            PrivateKey key = privateKeyFromString(privateKey, "EC");
            signer = new ECDSASigner(key, esCurve);
        }
        if (null == signer) {
            throw new NoSuchAlgorithmException("only support HMAC RSA ECDSA,current is " + algorithm);
        }
        return signer;
    }
    
    /**
     * 创建JWT头
     *
     * @param jwsAlgorithm 算法
     * @return JWT header
     */
    protected static JWSHeader header(JWSAlgorithm jwsAlgorithm) {
        return new JWSHeader(jwsAlgorithm, JOSEObjectType.JWT, null, null, null, null, null, null, null, null, null,
                true, null, null);
    }
    
    /**
     * 生成JWT payload部分
     *
     * @param issuer         签发者
     * @param subject        主题
     * @param expirationTime 有效期
     * @param tokenId        凭证ID
     * @param customClaims   自定义属性
     * @return JWTClaimsSet
     */
    protected static JWTClaimsSet claimsSet(String issuer, String subject, long expirationTime, String tokenId,
            Map<String, Object> customClaims) {
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder().subject(subject).issuer(issuer)
                .expirationTime(new Date(new Date().getTime() + expirationTime)).jwtID(tokenId);
        if (!CollectionUtils.isEmpty(customClaims)) {
            customClaims.forEach(claimsBuilder::claim);
        }
        return claimsBuilder.build();
    }
    
    /**
     * 对JWT进行验签
     *
     * @param jwt token
     * @return 成功或者失败
     */
    public static boolean verify(String jwt, String publicKey, String hacSecret) {
        boolean success = false;
        try {
            SignedJWT signedJWT = SignedJWT.parse(jwt);
            JWSAlgorithm algorithm = signedJWT.getHeader().getAlgorithm();
            JWSVerifier verifier = verifier(algorithm, publicKey, hacSecret);
            success = signedJWT.verify(verifier);
        } catch (Exception e) {
            log.debug("can't verify jwt", e);
        }
        return success;
    }
    
    /**
     * 对JWT进行验签
     *
     * @param jwt token
     * @return null/SignedJWT
     */
    public static SignedJWT verifyAndDecode(String jwt, String publicKey, String hacSecret) {
        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(jwt);
            JWSAlgorithm algorithm = signedJWT.getHeader().getAlgorithm();
            JWSVerifier verifier = verifier(algorithm, publicKey, hacSecret);
            if (!signedJWT.verify(verifier)) {
                signedJWT = null;
            }
        } catch (Exception e) {
            signedJWT = null;
            log.debug("can't verify jwt", e);
        }
        return signedJWT;
    }
    
    
    /**
     * 创建验签器
     *
     * @param jwsAlgorithm 算法
     * @param publicKey    公钥
     * @param hacSecret    HMAC密钥
     * @return JWSVerifier
     * @throws NoSuchAlgorithmException 当算法不是HMAC,RSA,ECDSA时抛出
     * @throws JOSEException            参数错误时抛出
     * @throws InvalidKeySpecException  密钥格式不正确时抛出
     */
    protected static JWSVerifier verifier(JWSAlgorithm jwsAlgorithm, String publicKey, String hacSecret)
            throws JOSEException, NoSuchAlgorithmException, InvalidKeySpecException {
        JWSVerifier verifier = null;
        String algorithm = jwsAlgorithm.getName();
        if (algorithm.contains("HS")) {
            //HMAC
            verifier = new MACVerifier(hacSecret);
        }
        if (algorithm.contains("RS")) {
            //RSA
            PublicKey key = publicKeyFromString(publicKey, "RSA");
            verifier = new RSASSAVerifier((RSAPublicKey) key);
        }
        if (algorithm.contains("ES")) {
            //ECDSA
            PublicKey key = publicKeyFromString(publicKey, "EC");
            verifier = new ECDSAVerifier((ECPublicKey) key);
        }
        if (null == verifier) {
            throw new NoSuchAlgorithmException("only support HMAC RSA ECDSA,current is " + algorithm);
        }
        return verifier;
    }
    
    
    /**
     * 将字符串形式的PublicKey转为PublicKey对象
     *
     * @param publicKey 字符串形式的公钥
     * @param algorithm 加密算法名称，RSA，DSA
     * @return PublicKey
     * @throws NoSuchAlgorithmException 算法名错误
     * @throws InvalidKeySpecException  密钥格式错误
     */
    public static PublicKey publicKeyFromString(String publicKey, String algorithm)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] publicBytes = Base64.decodeBase64(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        PublicKey pubKey = keyFactory.generatePublic(keySpec);
        return pubKey;
    }
    
    /**
     * 字符串形式的PrivateKey转为PrivateKey对象
     *
     * @param privateKey 字符串形式PrivateKey
     * @param algorithm  加密算法名称，RSA，DSA
     * @return PrivateKey
     * @throws NoSuchAlgorithmException 算法名错误
     * @throws InvalidKeySpecException  密钥格式错误
     */
    public static PrivateKey privateKeyFromString(String privateKey, String algorithm)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] publicBytes = Base64.decodeBase64(privateKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(publicBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        PrivateKey priKey = keyFactory.generatePrivate(keySpec);
        return priKey;
    }
}
