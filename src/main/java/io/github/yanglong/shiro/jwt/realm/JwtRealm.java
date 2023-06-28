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

package io.github.yanglong.shiro.jwt.realm;

import com.nimbusds.jwt.SignedJWT;
import io.github.yanglong.shiro.jwt.JwtHelper;
import io.github.yanglong.shiro.jwt.JwtLocalUserService;
import io.github.yanglong.shiro.jwt.JwtProperties;
import io.github.yanglong.shiro.jwt.BaseUser;
import io.github.yanglong.shiro.jwt.authc.JwtMatcher;
import io.github.yanglong.shiro.jwt.authc.JwtToken;
import org.apache.shiro.authc.AccountException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.pam.UnsupportedTokenException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.CollectionUtils;

import java.util.Map;
import java.util.Set;

/**
 * 用途描述：认证鉴权信息获取执行类
 * <p>
 * 认证filter生成token后，通过Subject（SecurityManager->Authenticator->Realm）进行登录，使用此类根据token获取用户信息
 * <p>
 * 授权注解处理器从此类根据用户获取相关权限信息
 *
 * @author YangLong
 * @version V1.0
 * @since 2023/6/24
 */
public class JwtRealm extends AuthorizingRealm {
    
    private JwtProperties jwtProperties;
    
    private JwtLocalUserService jwtLocalUserService;
    
    
    @Override
    public boolean isAuthorizationCachingEnabled() {
        return super.isAuthorizationCachingEnabled();
    }
    
    public JwtRealm(JwtProperties jwtProperties, JwtLocalUserService jwtLocalUserService) {
        super(new JwtMatcher());
        this.jwtProperties = jwtProperties;
        this.jwtLocalUserService = jwtLocalUserService;
    }
    
    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof JwtToken;
    }
    
    @Override
    public String getName() {
        return "jwtRealm";
    }
    
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        //load roles and permissions
        BaseUser user = (BaseUser) principals.getPrimaryPrincipal();
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        Set<String> roles = jwtLocalUserService.loadRoles(user);
        if (!CollectionUtils.isEmpty(roles)) {
            authorizationInfo.addRoles(roles);
        }
        Set<String> permissions = jwtLocalUserService.loadPermissions(user);
        if (!CollectionUtils.isEmpty(permissions)) {
            authorizationInfo.addStringPermissions(permissions);
        }
        return authorizationInfo;
    }
    
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        if (null != token.getPrincipal()) {
            JwtToken jwtToken = (JwtToken) token;
            String jwt = (String) jwtToken.getPrincipal();
            SignedJWT signedJWT = JwtHelper.verifyAndDecode(jwt, jwtProperties.getPublicKey(),
                    jwtProperties.getHacSecretKey());
            if (null == signedJWT) {
                throw new UnsupportedTokenException("can't decode JWT or expired");
            }
            try {
                Map<String, Object> claims = signedJWT.getJWTClaimsSet().getClaims();
                BaseUser user = jwtLocalUserService.bindAndCreateUser(claims);
                return new SimpleAuthenticationInfo(user, jwt, getName());
            } catch (Exception exception) {
                throw new UnknownAccountException("can't load user from JWT");
            }
        } else {
            throw new AccountException("token is null");
        }
    }
}
