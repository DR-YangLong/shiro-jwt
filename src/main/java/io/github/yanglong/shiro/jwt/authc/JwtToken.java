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

package io.github.yanglong.shiro.jwt.authc;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * 用途描述：Shiro filter从request创建的token，用于后续的认证授权
 *
 * @author YangLong
 * @version V1.0
 * @since 2023/6/24
 */
public class JwtToken implements AuthenticationToken {
    
    private final String token;
    
    public JwtToken(String token) {
        this.token = token;
    }
    
    
    @Override
    public Object getPrincipal() {
        return token;
    }
    
    @Override
    public Object getCredentials() {
        return token;
    }
}
