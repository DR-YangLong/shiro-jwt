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

import org.springframework.lang.NonNull;

import java.util.Map;
import java.util.Set;

/**
 * 用途描述：用于创建Jwt用户，绑定Jwt用户到本地系统，从本地系统加载权限信息
 *
 * @author YangLong
 * @version V1.0
 * @since 2023/6/23
 */
public interface JwtLocalUserService {
    
    /**
     * 从claims里取出用户ID，名称等等自定义的属性，然后根据约定的字段，将认证中心用户与本地系统用绑定，并创建JwtUser返回
     * <p>
     * 建议根据绑定键值做缓存
     *
     * @param claims JWT claims
     * @return 用户
     */
    @NonNull
    BaseUser bindAndCreateUser(Map<String, Object> claims);
    
    /**
     * 加载角色信息，建议缓存
     *
     * @param user 用户
     * @return 角色列表
     */
    Set<String> loadRoles(BaseUser user);
    
    /**
     * 加载权限信息，建议缓存
     *
     * @param user 用户
     * @return 权限列表
     */
    Set<String> loadPermissions(BaseUser user);
}
