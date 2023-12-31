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

import lombok.Data;

/**
 * 用途描述：基础用户
 *
 * @author YangLong
 * @version V1.0
 * @since 2023/6/24
 */
@Data
public class BaseUser {
    //用户ID
    private String id;
    //openId
    private String openId;
    //用户名
    private String userName;
    //工号
    private String jobId;
    //手机号
    private String mobile;
}
