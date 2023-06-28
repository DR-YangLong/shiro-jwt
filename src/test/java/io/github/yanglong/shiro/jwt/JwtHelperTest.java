package io.github.yanglong.shiro.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jwt.SignedJWT;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static java.time.temporal.ChronoUnit.SECONDS;

/**
 * 用途描述：
 *
 * @author YangLong
 * @version V1.0
 * @since 2023/6/23
 */
public class JwtHelperTest {
    
    public static void main(String[] args)
            throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, ParseException {
        String privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDIaMU/R7Z0C3lY"
                + "4En5/HJHNhNun3zDM7l1gDgtpu08WNDU8+5H2Zq6lvJOuhHcXg0/gb4UJYUSjY9Z"
                + "JyxzA2jCQYSGPwNtyhC9fEnNnT/80YqrXJYgYQJE9sOpw/K/sWfBWhfRSKhBbOD4"
                + "7oSq3s35X6lpkxkiDgp8qCwtnehNtwtwcAzt5OHy0rDzr18Hp4rG1ymLAFsctYbn"
                + "R423V09+E3g/lb9KOToL/6fyWUbUaQqZo0xSdvFp6AAjiunVMX88Y+44hxj4qEhI"
                + "8FHcwCRveqdtQozhnbcBufiMwj6+hbjD1zrvuyTDDibkMmKM6TkL6OIcJXCDJdff"
                + "g2W+jfSRAgMBAAECggEANSy/cWvouF+3AeL5HfBirgxmGYsNwol94vRzc4GAHuv9"
                + "9RMIHV5alLmqb0MlrA/0ee5F7fiKl4KiD2i6fYXhDPHvZONhWIct6+kHeBwKN12t"
                + "6ov1dX/n5z6GagwI494BhqcN/MTHiByIkORQpTna8xjzzYRvPb71/19r4WqtkbjP"
                + "1bmr3U9lOv51MYxpHhOaLc2fu1JT7tQUubIDbGSpu1/7PsvY+FQmBO2K41OtMguH"
                + "3GvkfXbHXEWTqemWqtwOJbsPf3Lmh0okJoRiQ6IAQoDP6SQwizJyzL0XnTymoC19"
                + "s+/EvACIS58YT8qWoohIUgrGQoWvyuVo1Lj7U3OGpQKBgQD8PYjFG9Sthis5COJx"
                + "lbT9nN8w5UaJqtptEpALHhL9ZGO5nMunSuJQ7rJfZlHZLdUUVuT4hNosjTjEv8Kd"
                + "HjlHrgXHfXJjvL8lzRLIZStUtf0wA783PdVMWKef/G+IjvMSQUt+OXusCRzfri64"
                + "z9cdmxQrAZmMRuZ+GOA7eHBDYwKBgQDLZXdEa4kqxpwhODMaT3kIXbCToErmM01V"
                + "yDE6v+Vggze44gTSstetqoVzSWdknZJ59sgl8GV51pctYcqO7W4gARA9Rv4Q4BhA"
                + "0OvC+IbmmFXQa/hZZySt3QbqoU7uHfaz20DdvJMO9ioMB8nyXDOWSme9Ki6URZfK"
                + "Gjs6OeJcewKBgQDPwm9QyueWNZiMVcEOBV0aN4euYmqDIfLfPBbg0Via1YE+dONZ"
                + "W9ilCLZq1YA8/f8vzZKzD9oUMA2+IKRPfYF4hOHFupHpjKF0pUD/RjU2hN+SGMP6"
                + "4Dc7txn6MJY9SGD1fEqOIRK4VJkvs+xP1QE+JWmrMpoibJOU8TBgS4dMOQKBgG2P"
                + "nG0ol9yI23UxdqWHhaSyAvmicHYL0G6SxaHl2ELiq9NVPE/asj8ECZqOQbl6/3nf"
                + "KvT0x1SX+RsjAB95Wca3i+3WHektLSNM5pJBmTkBecgpQL+3xZQ56Q3eEkxFq6w6"
                + "QHiwqW53vzJ3x5pbfBZKwhKtdCW+TwM4mgrFP1+dAoGAdN33rXGDE7MwRliE/Myc"
                + "N1UzCWQpLNEtSaXLroibcvqqtR/jXbgkyFGQnm/UmiBSMBBmqcsyFKDrC22t7POo"
                + "8QBWFbo+Puu7xbXlLX3+QzQ7Of6Ve5ceZN3delsBm7NtqxbeAdTdV7WSCg6OjTdu" + "W7789sopSgAb9q+BC2RYjA8=";
        String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyGjFP0e2dAt5WOBJ+fxy"
                + "RzYTbp98wzO5dYA4LabtPFjQ1PPuR9maupbyTroR3F4NP4G+FCWFEo2PWScscwNo"
                + "wkGEhj8DbcoQvXxJzZ0//NGKq1yWIGECRPbDqcPyv7FnwVoX0UioQWzg+O6Eqt7N"
                + "+V+paZMZIg4KfKgsLZ3oTbcLcHAM7eTh8tKw869fB6eKxtcpiwBbHLWG50eNt1dP"
                + "fhN4P5W/Sjk6C/+n8llG1GkKmaNMUnbxaegAI4rp1TF/PGPuOIcY+KhISPBR3MAk"
                + "b3qnbUKM4Z23Abn4jMI+voW4w9c677skww4m5DJijOk5C+jiHCVwgyXX34Nlvo30" + "kQIDAQAB";
        String hacSecret = null;
        Curve curve = Curve.P_521;
        Duration duration = Duration.of(300, SECONDS);
        String issuer = "io.github.yanglong";
        String subject = "login";
        String tokenId = "ed5v21eg2d1gex9dge2dx";
        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("openId", "5d21ge8ge");
        customClaims.put("userId", "12654");
        customClaims.put("userName", "王麻子");
        
        System.out.println("====RSA512 TEST BEGIN====");
        SignedJWT signedJWT = JwtHelper.signWithAlgorithm(JWSAlgorithm.RS512, privateKey, hacSecret, curve, issuer,
                subject, duration.toMillis(), tokenId, customClaims);
        String token = signedJWT.serialize();
        SignedJWT copy = JwtHelper.verifyAndDecode(token, publicKey, hacSecret);
        System.out.println("5d21ge8ge".equals(copy.getJWTClaimsSet().getClaim("openId")));
        System.out.println("====RSA512 TEST END====\n");
        
        System.out.println("====HMAC TEST BEGIN====");
        hacSecret = "r8Q$^iwvZMf7az!JAW6reOnu##7@zdII^FhAmaGLzyo0J#DkZ#ERVtMHoG^vC646";
        signedJWT = JwtHelper.signWithAlgorithm(JWSAlgorithm.HS512, privateKey, hacSecret, curve, issuer, subject,
                duration.toMillis(), tokenId, customClaims);
        token = signedJWT.serialize();
        copy = JwtHelper.verifyAndDecode(token, publicKey, hacSecret);
        System.out.println("5d21ge8ge".equals(copy.getJWTClaimsSet().getClaim("openId")));
        System.out.println("====HMAC TEST END====\n");
        
        System.out.println("====ES512 TEST BEGIN====");
        privateKey = "MF8CAQAwEAYHKoZIzj0CAQYFK4EEACMESDBGAgEBBEGDoOw+rEW2aOKu1KNvoTlSi+PghmdRWZOmTh6FukFM4PQYlITkz2R/qVd8KQS+1w/TTh0s80Dw320ir1i4nTcr2w==";
        publicKey = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBApWpPlUu1+0QSwhsFN+Y6Oen4eHDo8f2aUgO+x1s8l5lsS1IGwZlect++9i7zgY1kUr/g2+tmxfsRMfVKILAWAIA83L0ZnVCZXbEn8ht1nxXF1tjSb4BjGqOujYTQALR8Ei4sBHqJZ6H+jjXaMhVa1Wx9tHQtJt0p1bqPV/5vKdAjvM=";
        signedJWT = JwtHelper.signWithAlgorithm(JWSAlgorithm.ES512, privateKey, hacSecret, curve, issuer, subject,
                duration.toMillis(), tokenId, customClaims);
        token = signedJWT.serialize();
        copy = JwtHelper.verifyAndDecode(token, publicKey, hacSecret);
        System.out.println("5d21ge8ge".equals(copy.getJWTClaimsSet().getClaim("openId")));
        System.out.println("====ES512 TEST END====");
    }
    
    
}
