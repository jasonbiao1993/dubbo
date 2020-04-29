/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.dubbo.rpc.proxy;

import org.apache.dubbo.common.utils.ReflectUtils;
import org.apache.dubbo.rpc.Invoker;
import org.apache.dubbo.rpc.ProxyFactory;
import org.apache.dubbo.rpc.RpcException;
import org.apache.dubbo.rpc.service.Destroyable;
import org.apache.dubbo.rpc.service.GenericService;

import com.alibaba.dubbo.rpc.service.EchoService;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.apache.dubbo.common.constants.CommonConstants.COMMA_SPLIT_PATTERN;
import static org.apache.dubbo.rpc.Constants.INTERFACES;

/**
 * AbstractProxyFactory
 */
public abstract class AbstractProxyFactory implements ProxyFactory {
    private static final Class<?>[] INTERNAL_INTERFACES = new Class<?>[]{
            EchoService.class, Destroyable.class
    };

    @Override
    public <T> T getProxy(Invoker<T> invoker) throws RpcException {
        // 调用重载方法
        return getProxy(invoker, false);
    }

    @Override
    public <T> T getProxy(Invoker<T> invoker, boolean generic) throws RpcException {
        Set<Class<?>> interfaces = new HashSet<>();

        // 获取接口列表
        String config = invoker.getUrl().getParameter(INTERFACES);
        if (config != null && config.length() > 0) {
            // 切分接口列表
            String[] types = COMMA_SPLIT_PATTERN.split(config);
            if (types != null && types.length > 0) {
                for (int i = 0; i < types.length; i++) {
                    // TODO can we load successfully for a different classloader?.
                    interfaces.add(ReflectUtils.forName(types[i]));
                }
            }
        }

        // 为 http 和 hessian 协议提供泛化调用支持，参考 pull request #1827
        if (!GenericService.class.isAssignableFrom(invoker.getInterface()) && generic) {
            // 设置 GenericService.class 到数组中
            interfaces.add(com.alibaba.dubbo.rpc.service.GenericService.class);
        }

        interfaces.add(invoker.getInterface());

        // 设置服务接口类和 EchoService.class 到 interfaces 中
        interfaces.addAll(Arrays.asList(INTERNAL_INTERFACES));

        // 调用重载方法
        return getProxy(invoker, interfaces.toArray(new Class<?>[0]));
    }

    public abstract <T> T getProxy(Invoker<T> invoker, Class<?>[] types);

}
