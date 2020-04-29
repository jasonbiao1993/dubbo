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
package org.apache.dubbo.config;

import org.apache.dubbo.common.URL;
import org.apache.dubbo.common.URLBuilder;
import org.apache.dubbo.common.Version;
import org.apache.dubbo.common.bytecode.Wrapper;
import org.apache.dubbo.common.extension.ExtensionLoader;
import org.apache.dubbo.common.logger.Logger;
import org.apache.dubbo.common.logger.LoggerFactory;
import org.apache.dubbo.common.utils.ClassUtils;
import org.apache.dubbo.common.utils.CollectionUtils;
import org.apache.dubbo.common.utils.ConfigUtils;
import org.apache.dubbo.common.utils.NamedThreadFactory;
import org.apache.dubbo.common.utils.StringUtils;
import org.apache.dubbo.config.annotation.Service;
import org.apache.dubbo.config.bootstrap.DubboBootstrap;
import org.apache.dubbo.config.event.ServiceConfigExportedEvent;
import org.apache.dubbo.config.event.ServiceConfigUnexportedEvent;
import org.apache.dubbo.config.invoker.DelegateProviderMetaDataInvoker;
import org.apache.dubbo.config.support.Parameter;
import org.apache.dubbo.config.utils.ConfigValidationUtils;
import org.apache.dubbo.event.Event;
import org.apache.dubbo.event.EventDispatcher;
import org.apache.dubbo.metadata.WritableMetadataService;
import org.apache.dubbo.rpc.Exporter;
import org.apache.dubbo.rpc.Invoker;
import org.apache.dubbo.rpc.Protocol;
import org.apache.dubbo.rpc.ProxyFactory;
import org.apache.dubbo.rpc.cluster.ConfiguratorFactory;
import org.apache.dubbo.rpc.model.ApplicationModel;
import org.apache.dubbo.rpc.model.ServiceDescriptor;
import org.apache.dubbo.rpc.model.ServiceRepository;
import org.apache.dubbo.rpc.service.GenericService;
import org.apache.dubbo.rpc.support.ProtocolUtils;

import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static org.apache.dubbo.common.constants.CommonConstants.ANYHOST_KEY;
import static org.apache.dubbo.common.constants.CommonConstants.ANY_VALUE;
import static org.apache.dubbo.common.constants.CommonConstants.DEFAULT_METADATA_STORAGE_TYPE;
import static org.apache.dubbo.common.constants.CommonConstants.DUBBO;
import static org.apache.dubbo.common.constants.CommonConstants.DUBBO_IP_TO_BIND;
import static org.apache.dubbo.common.constants.CommonConstants.LOCALHOST_VALUE;
import static org.apache.dubbo.common.constants.CommonConstants.METADATA_KEY;
import static org.apache.dubbo.common.constants.CommonConstants.METHODS_KEY;
import static org.apache.dubbo.common.constants.CommonConstants.MONITOR_KEY;
import static org.apache.dubbo.common.constants.CommonConstants.PROVIDER_SIDE;
import static org.apache.dubbo.common.constants.CommonConstants.REGISTER_KEY;
import static org.apache.dubbo.common.constants.CommonConstants.REVISION_KEY;
import static org.apache.dubbo.common.constants.CommonConstants.SIDE_KEY;
import static org.apache.dubbo.common.constants.RegistryConstants.DYNAMIC_KEY;
import static org.apache.dubbo.common.utils.NetUtils.getAvailablePort;
import static org.apache.dubbo.common.utils.NetUtils.getLocalHost;
import static org.apache.dubbo.common.utils.NetUtils.isInvalidLocalHost;
import static org.apache.dubbo.common.utils.NetUtils.isInvalidPort;
import static org.apache.dubbo.config.Constants.DUBBO_IP_TO_REGISTRY;
import static org.apache.dubbo.config.Constants.DUBBO_PORT_TO_BIND;
import static org.apache.dubbo.config.Constants.DUBBO_PORT_TO_REGISTRY;
import static org.apache.dubbo.config.Constants.MULTICAST;
import static org.apache.dubbo.config.Constants.SCOPE_NONE;
import static org.apache.dubbo.remoting.Constants.BIND_IP_KEY;
import static org.apache.dubbo.remoting.Constants.BIND_PORT_KEY;
import static org.apache.dubbo.rpc.Constants.GENERIC_KEY;
import static org.apache.dubbo.rpc.Constants.LOCAL_PROTOCOL;
import static org.apache.dubbo.rpc.Constants.PROXY_KEY;
import static org.apache.dubbo.rpc.Constants.SCOPE_KEY;
import static org.apache.dubbo.rpc.Constants.SCOPE_LOCAL;
import static org.apache.dubbo.rpc.Constants.SCOPE_REMOTE;
import static org.apache.dubbo.rpc.Constants.TOKEN_KEY;
import static org.apache.dubbo.rpc.cluster.Constants.EXPORT_KEY;

public class ServiceConfig<T> extends ServiceConfigBase<T> {

    public static final Logger logger = LoggerFactory.getLogger(ServiceConfig.class);

    /**
     * A random port cache, the different protocols who has no port specified have different random port
     */
    private static final Map<String, Integer> RANDOM_PORT_MAP = new HashMap<String, Integer>();

    /**
     * A delayed exposure service timer
     */
    private static final ScheduledExecutorService DELAY_EXPORT_EXECUTOR = Executors.newSingleThreadScheduledExecutor(new NamedThreadFactory("DubboServiceDelayExporter", true));

    private static final Protocol protocol = ExtensionLoader.getExtensionLoader(Protocol.class).getAdaptiveExtension();

    /**
     * A {@link ProxyFactory} implementation that will generate a exported service proxy,the JavassistProxyFactory is its
     * default implementation
     */
    private static final ProxyFactory PROXY_FACTORY = ExtensionLoader.getExtensionLoader(ProxyFactory.class).getAdaptiveExtension();

    /**
     * Whether the provider has been exported
     */
    private transient volatile boolean exported;

    /**
     * The flag whether a service has unexported ,if the method unexported is invoked, the value is true
     */
    private transient volatile boolean unexported;

    private DubboBootstrap bootstrap;

    /**
     * The exported services
     */
    private final List<Exporter<?>> exporters = new ArrayList<Exporter<?>>();

    public ServiceConfig() {
    }

    public ServiceConfig(Service service) {
        super(service);
    }

    @Parameter(excluded = true)
    public boolean isExported() {
        return exported;
    }

    @Parameter(excluded = true)
    public boolean isUnexported() {
        return unexported;
    }

    public void unexport() {
        if (!exported) {
            return;
        }
        if (unexported) {
            return;
        }
        if (!exporters.isEmpty()) {
            for (Exporter<?> exporter : exporters) {
                try {
                    exporter.unexport();
                } catch (Throwable t) {
                    logger.warn("Unexpected error occured when unexport " + exporter, t);
                }
            }
            exporters.clear();
        }
        unexported = true;

        // dispatch a ServiceConfigUnExportedEvent since 2.7.4
        dispatch(new ServiceConfigUnexportedEvent(this));
    }

    public synchronized void export() {
        // 判断是否导出
        if (!shouldExport()) {
            // 不需要注册，<dubbo:service export="false"/>新标签 官网好像没有更新
            return;
        }

        if (bootstrap == null) {
            // BootStrap未启动，自动启动
            bootstrap = DubboBootstrap.getInstance();
            bootstrap.init();
        }

        // 1.检查并更新子设置
        checkAndUpdateSubConfigs();

        //init serviceMetadata
        // 初始化serviceMatadata属性
        // 版本 组名 接口类型 接口名称 实现接口的Bean实例
        serviceMetadata.setVersion(version);
        serviceMetadata.setGroup(group);
        serviceMetadata.setDefaultGroup(group);
        serviceMetadata.setServiceType(getInterfaceClass());
        serviceMetadata.setServiceInterfaceName(getInterface());
        serviceMetadata.setTarget(getRef());

        // 是否延迟加载
        if (shouldDelay()) {
            // 2.延迟注册
            // <dubbo:service delay="1000"/>
            DELAY_EXPORT_EXECUTOR.schedule(this::doExport, getDelay(), TimeUnit.MILLISECONDS);
        } else {
            // 3.直接注册
            doExport();
        }
    }

    private void checkAndUpdateSubConfigs() {
        // Use default configs defined explicitly with global scope
        // 使用全局范围显式定义的默认配置
        // <dubbo:provider/> <dubbo:protocol/>
        completeCompoundConfigs();
        // 检测各种对象是否为空，为空则新建，或者抛出异常
        checkDefault();
        checkProtocol();
        // if protocol is not injvm checkRegistry
        if (!isOnlyInJvm()) {
            // 如果protocol不是内部调用（injvm）
            // 检查registry设置
            checkRegistry();
        }

        // environment中的值覆盖service属性
        this.refresh();

        if (StringUtils.isEmpty(interfaceName)) {
            // interface属性必需
            throw new IllegalStateException("<dubbo:service interface=\"\" /> interface not allow null!");
        }

        // 检测 ref 是否为泛化服务类型
        if (ref instanceof GenericService) {
            // 设置 interfaceClass 为 GenericService.class
            // 如果实际Bean实现了GenericService接口，常用服务bean
            // interfaceClass = GenericService.class
            interfaceClass = GenericService.class;
            if (StringUtils.isEmpty(generic)) {
                // 设置 generic = "true"
                generic = Boolean.TRUE.toString();
            }
        // ref 非 GenericService 类型
        } else {
            try {
                // 不是GenericService接口类型，根据interfaceClass = Class.forName(interfaceName)
                interfaceClass = Class.forName(interfaceName, true, Thread.currentThread()
                        .getContextClassLoader());
            } catch (ClassNotFoundException e) {
                throw new IllegalStateException(e.getMessage(), e);
            }
            // 对 interfaceClass，以及 <dubbo:method> 标签中的必要字段进行检查
            // 检查接口方法都实现了
            checkInterfaceAndMethods(interfaceClass, getMethods());
            // 对 ref 合法性进行检测
            checkRef();
            // 设置 generic = "false"
            generic = Boolean.FALSE.toString();
        }
        // local 和 stub 在功能应该是一致的，用于配置本地存根
        if (local != null) {
            // 配置<dubbo:service local="true"/>时
            if ("true".equals(local)) {
                local = interfaceName + "Local";
            }
            Class<?> localClass;
            try {
                // 初始化代理类localClass = ClassforName(interfaceName+"Local")
                localClass = ClassUtils.forNameWithThreadContextClassLoader(local);
            } catch (ClassNotFoundException e) {
                throw new IllegalStateException(e.getMessage(), e);
            }
            if (!interfaceClass.isAssignableFrom(localClass)) {
                throw new IllegalStateException("The local implementation class " + localClass.getName() + " not implement interface " + interfaceName);
            }
        }
        if (stub != null) {
            //配置<dubbo:service stub="true"/>时
            if ("true".equals(stub)) {
                stub = interfaceName + "Stub";
            }
            Class<?> stubClass;
            try {
                //初始化代理类stubClass = ClassforName(interfaceName+"Stub")
                stubClass = ClassUtils.forNameWithThreadContextClassLoader(stub);
            } catch (ClassNotFoundException e) {
                throw new IllegalStateException(e.getMessage(), e);
            }
            if (!interfaceClass.isAssignableFrom(stubClass)) {
                throw new IllegalStateException("The stub implementation class " + stubClass.getName() + " not implement interface " + interfaceName);
            }
        }
        //检查若配置了local或stub，localClass或stubClass必须是interfaceClass的子类
        checkStubAndLocal(interfaceClass);
        // mock类校验
        ConfigValidationUtils.checkMock(interfaceClass, this);
        // 检查serviceconfig的属性
        ConfigValidationUtils.validateServiceConfig(this);
        appendParameters();
    }


    protected synchronized void doExport() {
        if (unexported) {
            throw new IllegalStateException("The service " + interfaceClass.getName() + " has already unexported!");
        }

        // 已注册的直接返回
        if (exported) {
            return;
        }
        exported = true;

        if (StringUtils.isEmpty(path)) {
            // 设置path默认值为接口名
            path = interfaceName;
        }
        // 导出服务
        doExportUrls();

        // dispatch a ServiceConfigExportedEvent since 2.7.4
        dispatch(new ServiceConfigExportedEvent(this));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private void doExportUrls() {
        // 前面创建服务仓库ServiceRepository
        ServiceRepository repository = ApplicationModel.getServiceRepository();
        // 将Service注册到服务仓库ServiceRepository的services中
        ServiceDescriptor serviceDescriptor = repository.registerService(getInterfaceClass());
        // 将Service注册到服务仓库ServiceRepository的providers中
        repository.registerProvider(
                getUniqueServiceName(),
                ref,
                serviceDescriptor,
                this,
                serviceMetadata
        );

        // 加载注册中心链接
        // 生成registryURLs格式如下
        // registry://mcip:2291/org.apache.dubbo.registry.RegistryService?application=dubbo-demo&backup=mcip:2292,mcip:2293&dubbo=2.0.2&pid=13252&registry=zookeeper&release=2.7.5&timestamp=1584191484814
        List<URL> registryURLs = ConfigValidationUtils.loadRegistries(this, true);

        // 遍历 protocols，并在每个协议下导出服务
        // <dubbo:protocol name="dubbo" port="${dubbo.port}" />
        for (ProtocolConfig protocolConfig : protocols) {
            // 服务路径=protocol的contexpath属性+service的path+group+version
            String pathKey = URL.buildKey(getContextPath(protocolConfig)
                    .map(p -> p + "/" + path)
                    .orElse(path), group, version);
            // In case user specified path, register service one more time to map it to path.
            // 如果指定了特殊路径，再次注入到服务仓库ServiceRepository的services中，
            // 未指定同名覆盖
            repository.registerService(pathKey, interfaceClass);
            // TODO, uncomment this line once service key is unified
            // 设置到serviceMetadata中
            serviceMetadata.setServiceKey(pathKey);
            // 注册
            doExportUrlsFor1Protocol(protocolConfig, registryURLs);
        }
    }

    private void doExportUrlsFor1Protocol(ProtocolConfig protocolConfig, List<URL> registryURLs) {
        String name = protocolConfig.getName();
        // 如果协议名为空，或空串，则将协议名变量设置为 dubbo
        if (StringUtils.isEmpty(name)) {
            // <dubbo:protocol name=""/>默认为dubbo
            name = DUBBO;
        }

        Map<String, String> map = new HashMap<String, String>();
        // 添加 side、版本、时间戳以及进程号等信息到 map 中
        // map.put("side","provider")
        map.put(SIDE_KEY, PROVIDER_SIDE);

        // map.put("release","2.7.5") dubbo版本号
        // map.put("dubbo","2.0.2")大版本号
        // map.put("pid",13252)进程号
        // map.put("timestamp","1584192663652")时间戳
        ServiceConfig.appendRuntimeParameters(map);
        AbstractConfig.appendParameters(map, getMetrics());
        // 通过反射将对象的字段信息添加到 map 中
        // map.put("application","dubbo-demo") 应用名
        AbstractConfig.appendParameters(map, getApplication());
        // map.put("module","") 模块名
        AbstractConfig.appendParameters(map, getModule());
        // remove 'default.' prefix for configs from ProviderConfig
        // appendParameters(map, provider, Constants.DEFAULT_KEY);
        // map.put("dynamic","true") service的dynamic默认true，动态注册
        // map.put("deprecated","false") service的deprecated默认false，作废标志
        AbstractConfig.appendParameters(map, provider);
        AbstractConfig.appendParameters(map, protocolConfig);

        // map.put("interface","org.study.service.UserService") service的path 默认接口名
        // map.put("generic","false") service的接口是否实现了GenericService
        AbstractConfig.appendParameters(map, this);

        // 方法设置
        // methods 为 MethodConfig 集合，MethodConfig 中存储了 <dubbo:method> 标签的配置信息
        if (CollectionUtils.isNotEmpty(getMethods())) {
            // 这段代码用于添加 Callback 配置到 map 中，代码太长，待会单独分析
            for (MethodConfig method : getMethods()) {
                // 添加 MethodConfig 对象的字段信息到 map 中，键 = 方法名.属性名。
                // 比如存储 <dubbo:method name="sayHello" retries="2"> 对应的 MethodConfig，
                // 键 = sayHello.retries，map = {"sayHello.retries": 2, "xxx": "yyy"}
                AbstractConfig.appendParameters(map, method, method.getName());
                String retryKey = method.getName() + ".retry";
                if (map.containsKey(retryKey)) {
                    String retryValue = map.remove(retryKey);
                    // 检测 MethodConfig retry 是否为 false，若是，则设置重试次数为0
                    if ("false".equals(retryValue)) {
                        map.put(method.getName() + ".retries", "0");
                    }
                }

                // 获取 ArgumentConfig 列表
                List<ArgumentConfig> arguments = method.getArguments();
                if (CollectionUtils.isNotEmpty(arguments)) {
                    for (ArgumentConfig argument : arguments) {
                        // convert argument type
                        // 检测 type 属性是否为空，或者空串
                        if (argument.getType() != null && argument.getType().length() > 0) {
                            Method[] methods = interfaceClass.getMethods();
                            // visit all methods
                            if (methods != null && methods.length > 0) {
                                for (int i = 0; i < methods.length; i++) {
                                    String methodName = methods[i].getName();
                                    // target the method, and get its signature
                                    // 比对方法名，查找目标方法
                                    if (methodName.equals(method.getName())) {
                                        Class<?>[] argtypes = methods[i].getParameterTypes();
                                        // one callback in the method
                                        if (argument.getIndex() != -1) {
                                            // 检测 ArgumentConfig 中的 type 属性与方法参数列表
                                            // 中的参数名称是否一致，不一致则抛出异常
                                            if (argtypes[argument.getIndex()].getName().equals(argument.getType())) {
                                                // 添加 ArgumentConfig 字段信息到 map 中，
                                                // 键前缀 = 方法名.index，比如:
                                                // map = {"sayHello.3": true}
                                                AbstractConfig.appendParameters(map, argument, method.getName() + "." + argument.getIndex());
                                            } else {
                                                throw new IllegalArgumentException("Argument config error : the index attribute and type attribute not match :index :" + argument.getIndex() + ", type:" + argument.getType());
                                            }
                                        } else {
                                            // multiple callbacks in the method
                                            for (int j = 0; j < argtypes.length; j++) {
                                                Class<?> argclazz = argtypes[j];
                                                // 从参数类型列表中查找类型名称为 argument.type 的参数
                                                if (argclazz.getName().equals(argument.getType())) {
                                                    AbstractConfig.appendParameters(map, argument, method.getName() + "." + j);
                                                    if (argument.getIndex() != -1 && argument.getIndex() != j) {
                                                        throw new IllegalArgumentException("Argument config error : the index attribute and type attribute not match :index :" + argument.getIndex() + ", type:" + argument.getType());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            // 用户未配置 type 属性，但配置了 index 属性，且 index != -1
                        } else if (argument.getIndex() != -1) {
                            // 添加 ArgumentConfig 字段信息到 map 中
                            AbstractConfig.appendParameters(map, argument, method.getName() + "." + argument.getIndex());
                        } else {
                            throw new IllegalArgumentException("Argument config must set index or type attribute.eg: <dubbo:argument index='0' .../> or <dubbo:argument type=xxx .../>");
                        }

                    }
                }
            } // end of methods for
        }

        // 检测 generic 是否为 "true"，并根据检测结果向 map 中添加不同的信息
        if (ProtocolUtils.isGeneric(generic)) {
            // genericService设置
            map.put(GENERIC_KEY, generic);
            map.put(METHODS_KEY, ANY_VALUE);
        } else {
            // 接口版本号，跟随jar包 例如：1.0-SNAPSHOT
            String revision = Version.getVersion(interfaceClass, version);
            if (revision != null && revision.length() > 0) {
                map.put(REVISION_KEY, revision);
            }

            // 接口的方法名数组
            // 为接口生成包裹类 Wrapper，Wrapper 中包含了接口的详细信息，比如接口方法名数组，字段信息等
            String[] methods = Wrapper.getWrapper(interfaceClass).getMethodNames();
            // 添加方法名到 map 中，如果包含多个方法名，则用逗号隔开，比如 method = init,destroy
            if (methods.length == 0) {
                logger.warn("No method found in service interface " + interfaceClass.getName());
                // 空方法标志map.put("methods","*")
                map.put(METHODS_KEY, ANY_VALUE);
            } else {
                // 将逗号作为分隔符连接方法名，并将连接后的字符串放入 map 中
                // 方法数组字符串map.put("methods","insert,update")
                map.put(METHODS_KEY, StringUtils.join(new HashSet<String>(Arrays.asList(methods)), ","));
            }
        }

        // 添加 token 到 map 中
        //  Service的token验证
        if (!ConfigUtils.isEmpty(token)) {
            if (ConfigUtils.isDefault(token)) {
                // 随机生成 token
                map.put(TOKEN_KEY, UUID.randomUUID().toString());
            } else {
                map.put(TOKEN_KEY, token);
            }
        }
        //init serviceMetadata attachments
        // map放入到serviceMetadata中
        serviceMetadata.getAttachments().putAll(map);

        // export service
        // 获取 host 和 port
        // 获取协议host，默认获取本机ip <dubbo:protocol host="" />
        String host = findConfigedHosts(protocolConfig, registryURLs, map);
        // 获取协议port，dubbo默认20880 <dubbo:protocol port="" />
        Integer port = findConfigedPorts(protocolConfig, name, map);
        // 组装 URL
        // 生成url格式如下
        // dubbo://192.168.56.1:20880/org.study.service.UserService?anyhost=true&application=dubbo-demo&bind.ip=192.168.56.1&bind.port=20880&deprecated=false&dubbo=2.0.2&dynamic=true&generic=false&interface=org.study.service.UserService&methods=getUserById,update,insert,transactionalTest,getUserByUserId,delete&pid=13252&release=2.7.5&revision=1.0-SNAPSHOT&side=provider&timestamp=1584192937036
        URL url = new URL(name, host, port, getContextPath(protocolConfig).map(p -> p + "/" + path).orElse(path), map);

        // You can customize Configurator to append extra parameters
        if (ExtensionLoader.getExtensionLoader(ConfiguratorFactory.class)
                .hasExtension(url.getProtocol())) {
            // 加载 ConfiguratorFactory，并生成 Configurator 实例，然后通过实例配置 url
            url = ExtensionLoader.getExtensionLoader(ConfiguratorFactory.class)
                    .getExtension(url.getProtocol()).getConfigurator(url).configure(url);
        }

        // 获取作用域scope属性
        String scope = url.getParameter(SCOPE_KEY);
        // don't export when none is configured

        // scope == "none",不注册，一般为null
        // 如果 scope = none，则什么都不做
        if (!SCOPE_NONE.equalsIgnoreCase(scope)) {

            // export to local if the config is not remote (export to remote only when config is remote)
            // scope != remote，导出到本地
            if (!SCOPE_REMOTE.equalsIgnoreCase(scope)) {
                // scope != "remote" ,注册到本地，一般为null会注册到本地
                exportLocal(url);
            }
            // export to remote if the config is not local (export to local only when config is local)
            // scope != "local" ,注册到注册表，一般为null会注册到注册表
            // scope != local，导出到远程
            if (!SCOPE_LOCAL.equalsIgnoreCase(scope)) {
                if (CollectionUtils.isNotEmpty(registryURLs)) {
                    for (URL registryURL : registryURLs) {
                        //if protocol is only injvm ,not register
                        if (LOCAL_PROTOCOL.equalsIgnoreCase(url.getProtocol())) {
                            // injvm,内部调用不注册
                            continue;
                        }

                        // url存在dynamic保留，不存在赋值为registryURL的dynamic属性值
                        url = url.addParameterIfAbsent(DYNAMIC_KEY, registryURL.getParameter(DYNAMIC_KEY));

                        // 监控的url
                        // 加载监视器链接
                        URL monitorUrl = ConfigValidationUtils.loadMonitor(this, registryURL);
                        if (monitorUrl != null) {
                            // 将监视器链接作为参数添加到 url 中
                            url = url.addParameterAndEncoded(MONITOR_KEY, monitorUrl.toFullString());
                        }
                        if (logger.isInfoEnabled()) {
                            if (url.getParameter(REGISTER_KEY, true)) {
                                logger.info("Register dubbo service " + interfaceClass.getName() + " url " + url + " to registry " + registryURL);
                            } else {
                                logger.info("Export dubbo service " + interfaceClass.getName() + " to url " + url);
                            }
                        }

                        // For providers, this is used to enable custom proxy to generate invoker
                        // provider代理属性 一般为null
                        String proxy = url.getParameter(PROXY_KEY);
                        if (StringUtils.isNotEmpty(proxy)) {
                            registryURL = registryURL.addParameter(PROXY_KEY, proxy);
                        }

                        // 创建一个AbstractProxyInvoker的子类实例new AbstractProxyInvoker(ref, interfaceClass,rul)
                        // 为服务提供类(ref)生成 Invoker
                        Invoker<?> invoker = PROXY_FACTORY.getInvoker(ref, (Class) interfaceClass, registryURL.addParameterAndEncoded(EXPORT_KEY, url.toFullString()));
                        // 包装器
                        // DelegateProviderMetaDataInvoker 用于持有 Invoker 和 ServiceConfig
                        DelegateProviderMetaDataInvoker wrapperInvoker = new DelegateProviderMetaDataInvoker(invoker, this);

                        // 默认DubboProtocol.export注册到远程注册表zookeeper中
                        // 导出服务，并生成 Exporter
                        Exporter<?> exporter = protocol.export(wrapperInvoker);
                        exporters.add(exporter);
                    }
                } else {
                    if (logger.isInfoEnabled()) {
                        logger.info("Export dubbo service " + interfaceClass.getName() + " to url " + url);
                    }
                    // 不存在注册中心，仅导出服务
                    Invoker<?> invoker = PROXY_FACTORY.getInvoker(ref, (Class) interfaceClass, url);
                    DelegateProviderMetaDataInvoker wrapperInvoker = new DelegateProviderMetaDataInvoker(invoker, this);

                    Exporter<?> exporter = protocol.export(wrapperInvoker);
                    exporters.add(exporter);
                }
                /**
                 * @since 2.7.0
                 * ServiceData Store
                 */
                WritableMetadataService metadataService = WritableMetadataService.getExtension(url.getParameter(METADATA_KEY, DEFAULT_METADATA_STORAGE_TYPE));
                if (metadataService != null) {
                    metadataService.publishServiceDefinition(url);
                }
            }
        }
        this.urls.add(url);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    /**
     * always export injvm
     */
    private void exportLocal(URL url) {
        URL local = URLBuilder.from(url)
                .setProtocol(LOCAL_PROTOCOL)
                .setHost(LOCALHOST_VALUE)
                .setPort(0)
                .build();
        Exporter<?> exporter = protocol.export(
                PROXY_FACTORY.getInvoker(ref, (Class) interfaceClass, local));
        exporters.add(exporter);
        logger.info("Export dubbo service " + interfaceClass.getName() + " to local registry url : " + local);
    }

    /**
     * Determine if it is injvm
     *
     * @return
     */
    private boolean isOnlyInJvm() {
        return getProtocols().size() == 1
                && LOCAL_PROTOCOL.equalsIgnoreCase(getProtocols().get(0).getName());
    }


    /**
     * Register & bind IP address for service provider, can be configured separately.
     * Configuration priority: environment variables -> java system properties -> host property in config file ->
     * /etc/hosts -> default network address -> first available network address
     *
     * @param protocolConfig
     * @param registryURLs
     * @param map
     * @return
     */
    private String findConfigedHosts(ProtocolConfig protocolConfig,
                                     List<URL> registryURLs,
                                     Map<String, String> map) {
        boolean anyhost = false;

        String hostToBind = getValueFromConfig(protocolConfig, DUBBO_IP_TO_BIND);
        if (hostToBind != null && hostToBind.length() > 0 && isInvalidLocalHost(hostToBind)) {
            throw new IllegalArgumentException("Specified invalid bind ip from property:" + DUBBO_IP_TO_BIND + ", value:" + hostToBind);
        }

        // if bind ip is not found in environment, keep looking up
        if (StringUtils.isEmpty(hostToBind)) {
            hostToBind = protocolConfig.getHost();
            if (provider != null && StringUtils.isEmpty(hostToBind)) {
                hostToBind = provider.getHost();
            }
            if (isInvalidLocalHost(hostToBind)) {
                anyhost = true;
                try {
                    logger.info("No valid ip found from environment, try to find valid host from DNS.");
                    hostToBind = InetAddress.getLocalHost().getHostAddress();
                } catch (UnknownHostException e) {
                    logger.warn(e.getMessage(), e);
                }
                if (isInvalidLocalHost(hostToBind)) {
                    if (CollectionUtils.isNotEmpty(registryURLs)) {
                        for (URL registryURL : registryURLs) {
                            if (MULTICAST.equalsIgnoreCase(registryURL.getParameter("registry"))) {
                                // skip multicast registry since we cannot connect to it via Socket
                                continue;
                            }
                            try (Socket socket = new Socket()) {
                                SocketAddress addr = new InetSocketAddress(registryURL.getHost(), registryURL.getPort());
                                socket.connect(addr, 1000);
                                hostToBind = socket.getLocalAddress().getHostAddress();
                                break;
                            } catch (Exception e) {
                                logger.warn(e.getMessage(), e);
                            }
                        }
                    }
                    if (isInvalidLocalHost(hostToBind)) {
                        hostToBind = getLocalHost();
                    }
                }
            }
        }

        map.put(BIND_IP_KEY, hostToBind);

        // registry ip is not used for bind ip by default
        String hostToRegistry = getValueFromConfig(protocolConfig, DUBBO_IP_TO_REGISTRY);
        if (hostToRegistry != null && hostToRegistry.length() > 0 && isInvalidLocalHost(hostToRegistry)) {
            throw new IllegalArgumentException("Specified invalid registry ip from property:" + DUBBO_IP_TO_REGISTRY + ", value:" + hostToRegistry);
        } else if (StringUtils.isEmpty(hostToRegistry)) {
            // bind ip is used as registry ip by default
            hostToRegistry = hostToBind;
        }

        map.put(ANYHOST_KEY, String.valueOf(anyhost));

        return hostToRegistry;
    }


    /**
     * Register port and bind port for the provider, can be configured separately
     * Configuration priority: environment variable -> java system properties -> port property in protocol config file
     * -> protocol default port
     *
     * @param protocolConfig
     * @param name
     * @return
     */
    private Integer findConfigedPorts(ProtocolConfig protocolConfig,
                                      String name,
                                      Map<String, String> map) {
        Integer portToBind = null;

        // parse bind port from environment
        String port = getValueFromConfig(protocolConfig, DUBBO_PORT_TO_BIND);
        portToBind = parsePort(port);

        // if there's no bind port found from environment, keep looking up.
        if (portToBind == null) {
            portToBind = protocolConfig.getPort();
            if (provider != null && (portToBind == null || portToBind == 0)) {
                portToBind = provider.getPort();
            }
            final int defaultPort = ExtensionLoader.getExtensionLoader(Protocol.class).getExtension(name).getDefaultPort();
            if (portToBind == null || portToBind == 0) {
                portToBind = defaultPort;
            }
            if (portToBind == null || portToBind <= 0) {
                portToBind = getRandomPort(name);
                if (portToBind == null || portToBind < 0) {
                    portToBind = getAvailablePort(defaultPort);
                    putRandomPort(name, portToBind);
                }
            }
        }

        // save bind port, used as url's key later
        map.put(BIND_PORT_KEY, String.valueOf(portToBind));

        // registry port, not used as bind port by default
        String portToRegistryStr = getValueFromConfig(protocolConfig, DUBBO_PORT_TO_REGISTRY);
        Integer portToRegistry = parsePort(portToRegistryStr);
        if (portToRegistry == null) {
            portToRegistry = portToBind;
        }

        return portToRegistry;
    }

    private Integer parsePort(String configPort) {
        Integer port = null;
        if (configPort != null && configPort.length() > 0) {
            try {
                Integer intPort = Integer.parseInt(configPort);
                if (isInvalidPort(intPort)) {
                    throw new IllegalArgumentException("Specified invalid port from env value:" + configPort);
                }
                port = intPort;
            } catch (Exception e) {
                throw new IllegalArgumentException("Specified invalid port from env value:" + configPort);
            }
        }
        return port;
    }

    private String getValueFromConfig(ProtocolConfig protocolConfig, String key) {
        String protocolPrefix = protocolConfig.getName().toUpperCase() + "_";
        String port = ConfigUtils.getSystemProperty(protocolPrefix + key);
        if (StringUtils.isEmpty(port)) {
            port = ConfigUtils.getSystemProperty(key);
        }
        return port;
    }

    private Integer getRandomPort(String protocol) {
        protocol = protocol.toLowerCase();
        return RANDOM_PORT_MAP.getOrDefault(protocol, Integer.MIN_VALUE);
    }

    private void putRandomPort(String protocol, Integer port) {
        protocol = protocol.toLowerCase();
        if (!RANDOM_PORT_MAP.containsKey(protocol)) {
            RANDOM_PORT_MAP.put(protocol, port);
            logger.warn("Use random available port(" + port + ") for protocol " + protocol);
        }
    }

    public void appendParameters() {
        URL appendParametersUrl = URL.valueOf("appendParameters://");
        List<AppendParametersComponent> appendParametersComponents = ExtensionLoader.getExtensionLoader(AppendParametersComponent.class).getActivateExtension(appendParametersUrl, (String[]) null);
        appendParametersComponents.forEach(component -> component.appendExportParameters(this));
    }

    /**
     * Dispatch an {@link Event event}
     *
     * @param event an {@link Event event}
     * @since 2.7.5
     */
    private void dispatch(Event event) {
        EventDispatcher.getDefaultExtension().dispatch(event);
    }

    public DubboBootstrap getBootstrap() {
        return bootstrap;
    }

    public void setBootstrap(DubboBootstrap bootstrap) {
        this.bootstrap = bootstrap;
    }
}