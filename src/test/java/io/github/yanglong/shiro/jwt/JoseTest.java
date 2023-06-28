package io.github.yanglong.shiro.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.apache.commons.codec.binary.Base64;

/**
 * 用途描述：
 *
 * @author YangLong
 * @version V1.0
 * @since 2023/6/23
 */
public class JoseTest {
    
    public static void main(String[] args) throws JOSEException {
        ECKey ecJWK = new ECKeyGenerator(Curve.SECP256K1)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("123").generate();
        byte[] privateKeyBytes =  ecJWK.toPrivateKey().getEncoded();
        byte[] publicKeyBytes =  ecJWK.toPublicKey().getEncoded();
        
        System.out.println("privatekey:" + Base64.encodeBase64String(privateKeyBytes));
        System.out.println("publickey:" + Base64.encodeBase64String(publicKeyBytes));
    }
}
