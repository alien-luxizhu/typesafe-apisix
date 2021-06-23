# APISIX源码分析——路由匹配
 > 摘自 https://juejin.cn/post/6933768239008874510

# 0x00 说明
本文基于APISIX 2.3 版本进行分析。

# 0x01 入口
APISIX 是基于在 OpenResty 上构建的一个应用，而 OpenResty 本质上是 Nginx，因此，要找到 APISIX 进行路由匹配和流量代理的入口，还是需要看 nginx.conf 配置文件。

当我在开发机器上启动 APISIX 之后，执行 ps -ef | grep nginx 命令，可以看到如下进程
```
root      7132     1  0 00:17 ?        00:00:00 nginx: master process openresty -p /usr/local/apisix -c /usr/local/apisix/conf/nginx.conf
nobody    7133  7132  0 00:17 ?        00:00:00 nginx: worker process
nobody    7134  7132  0 00:17 ?        00:00:00 nginx: worker process
nobody    7135  7132  0 00:17 ?        00:00:00 nginx: worker process
nobody    7136  7132  0 00:17 ?        00:00:00 nginx: worker process
nobody    7137  7132  0 00:17 ?        00:00:00 nginx: cache manager process
root      7139  7132  0 00:17 ?        00:00:00 nginx: privileged agent process
```
master 后面跟着的启动命令 nginx: master process openresty -p /usr/local/apisix -c /usr/local/apisix/conf/nginx.conf 即

APISIX 启动时真正执行的命令，需要查看的 nginx.conf 文件的路径也在其中。（关于 APISIX 启动过程，可参考前一篇 APISIX(v1.5)启动过程源码分析）

/usr/local/apisix/conf/nginx.conf 中有关 APISIX 路由匹配的配置如下（缩略）
```
    server {
        # 监听 9080/9443 端口，这两个端口分别是 apisix 监听应 http/https 协议的默认端口
        listen 9080 reuseport;
        listen 9443 ssl http2 reuseport;

        listen [::]:9080 reuseport;
        listen [::]:9443 ssl http2 reuseport;
    
        ……
        
        # 用 / 匹配所有来自客户端的请求
        location / {
            ……
            # 在openresty 的 access_by_lua_block 执行阶段，将匹配到的请求挂载到 apisix.http_access_phase() 函数
            access_by_lua_block {
                # apisix.http_access_phase() 即 /usr/local/apisix/apisix/init.lua 中的函数 http_access_phase()
                # /usr/local/apisix 是我开发机上的 apisix 的运行时目录
                apisix.http_access_phase()
            }
            
            ……
        }
    }
```
# 0x01 http_access_phase 函数
## ngx.ctx 分析
```
function _M.http_access_phase()
    local ngx_ctx = ngx.ctx
    -- always fetch table from the table pool, we don't need a reused api_ctx
    local api_ctx = core.tablepool.fetch("api_ctx", 0, 32)
    ngx_ctx.api_ctx = api_ctx

    core.ctx.set_vars_meta(api_ctx)
    ……
```
ngx.ctx 是一个 table，用来存储基于请求的 Lua 环境数据，生命周期与当前请求想用，因此可以做到但个请求内不同执行阶段的数据共享。当前请求的子请求，也会拥有一份自己的 ngx.ctx。这个有点像 Java 里面的ThreadLocal。

ngx.ctx 相关参考：

[不同阶段共享变量](https://moonbingbing.gitbooks.io/openresty-best-practices/content/openresty/share_var.html)

[ngx.var与ngx.ctx的区别](https://blog.csdn.net/u011944141/article/details/89145362)

[对 ngx.ctx 的一次 hack](https://segmentfault.com/a/1190000009485897)

[也谈 ngx.ctx 继承问题](https://ms2008.github.io/2018/11/26/ngx-ctx-inheirt/)

上面代码代码中 local ngx_ctx = ngx.ctx ，此时 ngx.ctx 还是一个空的table，里面什么也没有。

core.ctx.set_vars_meta 函数如下
```
-- 通过 Luajit 用 FFI 方式获取Nginx变量，既快又轻便，性能远高于 ngx.var.*的方式。 
local get_request  = require("resty.ngxvar").request
-- 根据名称返回 Nginx 变量的值
local get_var      = require("resty.ngxvar").fetch
……

    local var_methods = {
        method = ngx.req.get_method,
        cookie = function () return ck:new() end
    }

    local ngx_var_names = {
        upstream_scheme            = true,
        upstream_host              = true,
        upstream_upgrade           = true,
        upstream_connection        = true,
        upstream_uri               = true,

        upstream_mirror_host       = true,

        upstream_cache_zone        = true,
        upstream_cache_zone_info   = true,
        upstream_no_cache          = true,
        upstream_cache_key         = true,
        upstream_cache_bypass      = true,
        upstream_hdr_expires       = true,
        upstream_hdr_cache_control = true,
    }

    local mt = {
        __index = function(t, key)
            if type(key) ~= "string" then
                error("invalid argument, expect string value", 2)
            end

            local val
            local method = var_methods[key]
            if method then
                val = method()

            elseif core_str.has_prefix(key, "cookie_") then
                local cookie = t.cookie
                if cookie then
                    local err
                    val, err = cookie:get(sub_str(key, 8))
                    if not val then
                        log.warn("failed to fetch cookie value by key: ",
                                 key, " error: ", err)
                    end
                end

            elseif core_str.has_prefix(key, "http_") then
                key = key:lower()
                key = re_gsub(key, "-", "_", "jo")
                val = get_var(key, t._request)

            elseif core_str.has_prefix(key, "graphql_") then
                -- trim the "graphql_" prefix
                key = sub_str(key, 9)
                val = get_parsed_graphql(t)[key]

            elseif key == "route_id" then
                val = ngx.ctx.api_ctx and ngx.ctx.api_ctx.route_id

            elseif key == "service_id" then
                val = ngx.ctx.api_ctx and ngx.ctx.api_ctx.service_id

            elseif key == "consumer_name" then
                val = ngx.ctx.api_ctx and ngx.ctx.api_ctx.consumer_name

            elseif key == "route_name" then
                val = ngx.ctx.api_ctx and ngx.ctx.api_ctx.route_name

            elseif key == "service_name" then
                val = ngx.ctx.api_ctx and ngx.ctx.api_ctx.service_name

            else
                -- t._request --> var._request --> get_request()
                -- 当 key 不是上面这些，从 Nginx 变量中获取 key 的值
                -- e.g. key = uri, request_method, host, remote_addr 的时候
                val = get_var(key, t._request)
            end

            if val ~= nil then
                -- 在不调用元表的情况下，给t[key]赋值为val
                -- t 即调用 setmetatable 中的表 var
                rawset(t, key, val) -- (1)
                -- t.key = val (2)
            end

            return val
        end,

        __newindex = function(t, key, val)
            if ngx_var_names[key] then
                ngx_var[key] = val
            end

            -- log.info("key: ", key, " new val: ", val)
            rawset(t, key, val) -- (3) 
            -- t.key = val   (4反例
        end,
    }

function _M.set_vars_meta(ctx)
    local var = tablepool.fetch("ctx_var", 0, 32)
    -- 获取 Nginx 变量
    var._request = get_request()
    -- 为 var 设置元表 mt
    setmetatable(var, mt)

    ctx.var = var
end
```
如果在 APISIX 要获取的当前请求的 uri，那么在对应地会有这样的调用代码： ngx_ctx.api_ctx.var.uri ，由于 var 表本身是没有这些 key 的，所以会进入 var 的元表的 __index 函数进行查找，经过一系列判断之后，进入 val = get_var(key, t._request)。

t._request 即 var._request， var._request 调用了 require("resty.ngxvar").request，获得当前请求的请求对象，get_var(key, t._request) 即从当前请求对象的 Nginx 变量中获取 key 的值。

整个过程相当于直接调用 ngx.var.uri，为什么绕了这样一圈来获取呢，主要是利用了 lua-var-nginx-module

这个库，性能比直接调用 ngx.var.uri更好，ngx.var.* 调用耗费性能。并且如果我们试图在一个请求中获取多个变量，可以将其缓存在Lua代码中，在其他地方调用。

## rawset(t, key, val) 分析
如果把 (1) 换成 (2)，并不会引发 stack overflow，在 __index 中也使用 rawset， 我理解是为了防止出错。

如果把 (3) 换成 (4)，那么会引发stack overflow，因为在 __newindex 中进行赋值给指定下标 table[key] = value 的操作，需要进入到 table 的元表，也就是又回到了 __newindex，继续执行 table[key] = value，引发了死循环，直到 stack overflow。

参考：

[深度理解Lua中的table元方法](https://www.jianshu.com/p/9fa3dae786b4)

在执行基本的路由匹配之后，t 表的数据在元方法 __index 入口处如下
```
{
  _request = cdata<void *>: 0x017b90c0
}
```
在经过多次查找 key 后，比如 key = uri，host， request_method， remote_addr 等，执行到 __index 的 return val 处，t 表的数据如下
```
{
  _request = cdata<void *>: 0x012d89a0,
  host = "127.0.0.1",
  remote_addr = "127.0.0.1",
  request_method = "GET",
  uri = "/",
  <metatable> = {
    __index = <function 1>,
    __newindex = <function 2>
  }
}
```
至于什么时候会去查找 key = uri，host， request_method， remote_addr，下面会说。

## load and run global rule 分析
接下来是加载 router 的 global_rules
```
if router.global_rules and router.global_rules.values
       and #router.global_rules.values > 0 then
       ……
    
```
router 的 global_rules 赋值分为3个步骤

## global_rules: step 1
发生在 /apisix/cli/etcd.init() 函数中
```
for _, dir_name in ipairs({"/routes", "/upstreams", "/services",
                                   "/plugins", "/consumers", "/node_status",
                                   "/ssl", "/global_rules", "/stream_routes",
                                   "/proto", "/plugin_metadata"}) do

            local key =  (etcd_conf.prefix or "") .. dir_name .. "/"

            local put_url = host .. "/v3/kv/put"
            local post_json = '{"value":"' .. base64_encode("init_dir")
                              .. '", "key":"' .. base64_encode(key) .. '"}'
            ……

            local res, err = request({
                url = put_url,
                method = "POST",
                source = ltn12.source.string(post_json),
                sink = ltn12.sink.table(response_body),
                headers = headers
            }, yaml_conf)
            ……
        end
```
在 apisix 的启动阶段，执行 init etcd 命令后，该命令会初始化 APISIX 在 etcd 中需要的目录，这个过程与 OpenResty 的执行阶段没什么关系，是发生在 OpenResty 启动之前的事情，以 global_rules 举例，这个命令会在 etcd 中创建一个 key = /apisix/global_rules/，value = init_dir 的数据。

## global_rules: step 2
发生在 /apisix/router.http_init_worker() 函数中。
```
    local global_rules, err = core.config.new("/global_rules", {
            automatic = true,
            item_schema = core.schema.global_rule,
            checker = plugin_checker,
        })
    if not global_rules then
        error("failed to create etcd instance for fetching /global_rules : "
              .. err)
    end
    _M.global_rules = global_rules
```
在 init_worker_by_lua_block 阶段，即 worker 启动的时候，创建 etcd 客户端连接，watch /global_rules 目录下的资源，然后返回一个包装过的 etcd_cli 对象。但是这里返回的 etcd_cli 对象 并未加载该目录下的资源，所以这里的 global_rules.values 是 nil。

## global_rules: step 3
真正从 etcd 指定目录下加载资源并且赋值到先前返回的etcd_cli 对象是一个异步操作的过程， 这个过程在 /apisix/core/config_etcd.lua 的 sync_data() 函数中
```
local function sync_data(self)
        ……
                if data_valid then
                    changed = true
                    insert_tab(self.values, item)
                    self.values_hash[key] = #self.values

                    item.value.id = key
                    item.clean_handlers = {}

                    if self.filter then
                        self.filter(item)
                    end
                end
        ……
    return self.values
end
```
这个函数的是 APISIX 和 etcd 进行资源 fetch 的核心过程，比较复杂，会在其他专题中整理。

经过这个异步操作，router 的 global_rules 赋值工作已经完成，在 apisix.http_access_phase() 那里可以通过 router.global_rules.values 来获取已经加载的 global_rules。

获取到 global_rules 后，下面去执行一些 global_rules 的操作。
```
        local plugins = core.tablepool.fetch("plugins", 32, 0)
        local values = router.global_rules.values
        for _, global_rule in config_util.iterate_values(values) do
            core.log.warn("global_rule: ", require("apisix.inspect")(global_rule))
            api_ctx.conf_type = "global_rule"
            api_ctx.conf_version = global_rule.modifiedIndex
            api_ctx.conf_id = global_rule.value.id

            core.table.clear(plugins)
            -- 过滤插件,获取 global_rule 对应的 schema， function 等等
            -- 但其实这里有个问题，即请求在执行路由匹配之前，先执行全局插件的逻辑
            -- 感觉这样会有一些恶意请求可以通过全局插件的逻辑来执行恶意行为
            api_ctx.plugins = plugin.filter(global_rule, plugins)
            run_plugin("rewrite", plugins, api_ctx)
            run_plugin("access", plugins, api_ctx)
        end

        core.tablepool.release("plugins", plugins)
        api_ctx.plugins = nil
        api_ctx.conf_type = nil
        api_ctx.conf_version = nil
        api_ctx.conf_id = nil

        api_ctx.global_rules = router.global_rules
```
以 limit-count 插件为例，经过 plugin.filter(global_rule, plugins) 之后获得的 api_ctx.plugins 如下
```
{ {
    access = <function 1>,
    check_schema = <function 2>,
    name = "limit-count",
    priority = 1002,
    schema = {
      ["$comment"] = "this is a mark for our injected plugin schema",
      dependencies = {
        policy = {
          oneOf = { {
              properties = {
                policy = {
                  enum = { "local" }
                }
              }
            }, {
              properties = {
                policy = {
                  enum = { "redis" }
                },
                redis_host = {
                  minLength = 2,
                  type = "string"
                },
                redis_password = {
                  minLength = 0,
                  type = "string"
                },
                redis_port = {
                  default = 6379,
                  minimum = 1,
                  type = "integer"
                },
                redis_timeout = {
                  default = 1000,
                  minimum = 1,
                  type = "integer"
                }
              },
              required = { "redis_host" }
            }, {
              properties = {
                policy = {
                  enum = { "redis-cluster" }
                },
                redis_cluster_nodes = {
                  items = {
                    maxLength = 100,
                    minLength = 2,
                    type = "string"
                  },
                  minItems = 2,
                  type = "array"
                },
                redis_password = {
                  minLength = 0,
                  type = "string"
                },
                redis_timeout = {
                  default = 1000,
                  minimum = 1,
                  type = "integer"
                }
              },
              required = { "redis_cluster_nodes" }
            } }
        }
      },
      properties = {
        count = {
          exclusiveMinimum = 0,
          type = "integer"
        },
        disable = {
          type = "boolean"
        },
        key = {
          default = "remote_addr",
          enum = { "remote_addr", "server_addr", "http_x_real_ip", "http_x_forwarded_for", "consumer_name", "service_id" },
          type = "string"
        },
        policy = {
          default = "local",
          enum = { "local", "redis", "redis-cluster" },
          type = "string"
        },
        rejected_code = {
          default = 503,
          maximum = 599,
          minimum = 200,
          type = "integer"
        },
        time_window = {
          exclusiveMinimum = 0,
          type = "integer"
        }
      },
      required = { "count", "time_window" },
      type = "object"
    },
    version = 0.4
  }, {
    count = 2,
    key = "remote_addr",
    policy = "local",
    redis_timeout = 1000,
    rejected_code = 503,
    time_window = 60
  } }
```
api_ctx.plugins 这个 table 的结构比较特殊，首先它是个数组。其次，以下标为 1 开始，下标为 1 和下标为 2 的两个元素之间有关联关系，类推 3和 4，5 和 6 ……

从上面 api_ctx.plugins 的内容来分析，下标为 1 的元素是 limit-count 插件的元数据/元属性等等融合在一起的数据，而下标为 2 的元素是用户配置的 limit-count 插件的实例参数配置。

所以下面 run_plugin 的函数中遍历 api_ctx.plugins 时，for 循环的步进长度是 2。

## run_plugin 执行插件
```
            run_plugin("rewrite", plugins, api_ctx)
            run_plugin("access", plugins, api_ctx)

        for i = 1, #plugins, 2 do
            local phase_func = plugins[i][phase]
            -- phase_func 指向 插件的 phase 阶段对应的函数
            if phase_func then
                -- plugins[i + 1] 就是插件函数的入参 conf， api_ctx 就是插件函数的入参 ctx
                local code, body = phase_func(plugins[i + 1], api_ctx)
                if code or body then
                    if code >= 400 then
                        core.log.warn(plugins[i].name, " exits with http status code ", code)
                    end

                    core.response.exit(code, body)
                end
            end
        end
```
调用 run_plugin 函数时，传入 rewrite 或者 access 这样的 phase，然后在 run_plugin 函数中根据传入的 phase 来调用插件相应的 phase 阶段的函数。

比如在全局规则下配置了 limit-count 插件，在调用 run_plugin 函数传入了 access 这个执行阶段，那么在 run_plugin 函数中就会调用到 limit-count 插件的 access 函数。

## release table
```
        -- 回收 plugins 这个table
        core.tablepool.release("plugins", plugins)

        api_ctx.plugins = nil
        api_ctx.conf_type = nil
        api_ctx.conf_version = nil
        api_ctx.conf_id = nil
         
        -- 将执行过的 global_rules 保存在 api_ctx 中
        api_ctx.global_rules = router.global_rules
```
当 global_rules 执行结束之后，回收上面分配的 table，并且将 api_ctx 中关于插件的部分清空。

因为 global_rules 的执行在请求进行路由匹配之前，而当请求完成路由匹配后，就会执行配置在 router/srvice 上的一些插件，所以这里回收 table 和清空插件配置，是防止干扰下面的插件执行的环境，同时在 api_ctx 中保留执行过的 global_rules 的数据。

## delete_uri_tail_slash 去除 uri 结尾的反斜杠
```
    local uri = api_ctx.var.uri
    if local_conf.apisix and local_conf.apisix.delete_uri_tail_slash then
        if str_byte(uri, #uri) == str_byte("/") then
            api_ctx.var.uri = str_sub(api_ctx.var.uri, 1, #uri - 1)
            core.log.info("remove the end of uri '/', current uri: ",
                          api_ctx.var.uri)
        end
    end
```
这段比较简单，配置文件中有个开关 delete_uri_tail_slash，是否删除 URI 尾部的 /，日志也表明了这段代码的作用。

## has_route_not_under_apisix 自定义路由前缀
```
    if router.api.has_route_not_under_apisix() or
        core.string.has_prefix(uri, "/apisix/")
    then
        local matched = router.api.match(api_ctx)
        if matched then
            return
        end
    end
```
判断用户自定义的路由中是否有不以 /apisix/ 作为前缀的，比如在配置文件中定义如下
```
plugin_attr:
    prometheus:
        export_uri: /metrics
```
自定义 prometheus 插件暴露的监控地址，不以 /apisix/ 作为前缀，那么 router.api.has_route_not_under_apisix() 就负责识别这种请求。has_route_not_under_apisix 这个函数在 APISIX 启动的时候从配置文件中读取所有用户自定义的 URI，判断是否有/apisix/为前缀的，用模块级的变量进行全局缓存。

另一种就是以 /apisix/ 为前缀的请求，core.string.has_prefix(uri, "/apisix/") 负责识别这类请求，一般这种请求都来自于 APISIX 暴露的 CP 面的 API，以及一些插件暴露的 API，不是需要进行代理的客户端的 DP 面的。

~~我感觉这一类 CP 的请求的判断应该放在路由匹配之后。因为所有的请求都会走一遍这段代码逻辑。而在真实场景中，来自客户端的 DP 面的请求的数量极应该远远大于来自 APISIX CP 面的请求。在 DP 面匹配 404 之后，再判断是否是 CP 面的请求。~~

这里把 CP 面的请求放在前面，是基于 APISIX 自身的某些机制来考虑的。比如 jwt-auth 插件的运作机制，需要客户端先请求 CP 面的 API apisix/plugin/jwt/sign?key=user-key 来申请颁发 jwt，并在执行 DP 面的请求时携带。

如果先执行 DP 面的路由匹配，后执行申请颁发 jwt 的 CP 面路由匹配，后那么当客户端设置了路由匹配条件为 /*， 然后执行申请颁发 jwt 请求，则这个请求被 /* 匹配上，被当成 DP 面的请求，直接校验是否携带 jwt，当然不可能携带，于是返回 401，出现逻辑错误。

识别出来的来自 CP 面的请求，交给 apisix.api_router.lua 模块处理。

## match 路由匹配
```
    router.router_http.match(api_ctx)

    local route = api_ctx.matched_route
    if not route then
        core.log.info("not find any matched route")
        return core.response.exit(404,
                    {error_msg = "404 Route Not Found"})
    end
```
这里就是 APISIX 进行路由匹配真正的入口了。

APISIX 共有 3 种路由匹配模式

- radixtree_uri: （默认）只使用 uri 作为主索引。基于 radixtree 引擎，支持全量和深前缀匹配，
更多见 [如何使用 router-radixtree](https://juejin.cn/router-radixtree.md)。
  * 绝对匹配：完整匹配给定的 uri ，比如 /foo/bar，/foo/glo。
  * 前缀匹配：末尾使用 * 代表给定的 uri 是前缀匹配。比如 /foo*，则允许匹配 /foo/、/foo/a和/foo/b等。
  * 匹配优先级：优先尝试绝对匹配，若无法命中绝对匹配，再尝试前缀匹配。
  * 任意过滤属性：允许指定任何 Nginx 内置变量作为过滤条件，比如 URL 请求参数、请求头、cookie 等。
- radixtree_uri_with_parameter: 同 radixtree_uri 但额外有参数匹配的功能（适配 restful 风格）。
- radixtree_host_uri: 使用 host + uri 作为主索引（基于 radixtree 引擎），对当前请求会同时匹配 host 和 uri，支持的匹配条件与 radixtree_uri 基本一致。

## step1: 初始化路由
以 radixtree_uri 为例，在 APISIX 启动的 init_worker_by_lua_block 阶段，经过层层函数调用
```
/apisix/init.lua#http_init_worker() -> /apisix/router#http_init_worker() -> /apisix/router#attach_http_router_common_methods() -> /apisix/http/route#init_worker()
```
/apisix/http/route#init_worker()代码如下
```
    local user_routes, err = core.config.new("/routes", {
            automatic = true,
            item_schema = core.schema.route,
            checker = check_route,
            filter = filter,
        })
    if not user_routes then
        error("failed to create etcd instance for fetching /routes : " .. err)
    end

    return user_routes
```
这也是一个从 etcd 中初始化数据的操作，主要是 watch /apisix/routes 目录下的资源。

## step2: 检查缓存版本号
检查版本号函数在 apisix.http.router.radixtree_uri.lua 模块内
```
function _M.match(api_ctx)
    local user_routes = _M.user_routes
    if not cached_version or cached_version ~= user_routes.conf_version then
        -- 创建了
        uri_router = base_router.create_radixtree_uri_router(user_routes.values,
                                                             uri_routes, false)
        -- 检查缓存版本号
        cached_version = user_routes.conf_version
    end

    if not uri_router then
        core.log.error("failed to fetch valid `uri` router: ")
        return true
    end

    return base_router.match_uri(uri_router, match_opts, api_ctx)
end
```
_M.user_routes 的来源有点绕，其实还是在启动的时候 etcd 中返回的数据。
```
/apisix/router#http_init_worker() 函数    
    local router_http = require("apisix.http.router." .. router_http_name)
    attach_http_router_common_methods(router_http) -- router_http 即 apisix.http.router.radixtree_uri.lua

/apisix/router#attach_http_router_common_methods() 函数
    -- http_router 是 apisix.http.router.radixtree_uri.lua
    -- http_route 是 apisix.http.route.lua
    http_router.user_routes = http_route.init_worker(filter) -- user_routes 即 /apisix/http/route#init_worker() 函数返回的 user_routes
```

由于 etcd 返回的 user_routes 数据是一个动态变化的数据，它会一直监控 etcd 中 /apisix/routes 目录下数据的变化，每当数据变更时，user_routes.conf_version + 1，所以 user_routes 的数据可以看作是 etcd 中最新数据。

cached_version 首先是一个模块变量，相当于 worker 级别的缓存，而在 APISIX 启动之后，cached_version 是一个 nil 值，所以这句 if not cached_version or cached_version ~= user_routes.conf_version then 判断是对比 etcd 中的最新数据和 worker 级别中缓存数据的版本是否一致，不一致则进行重建路由。

## step3: 重建路由
重建路由函数发生在 apisix.http.route.lua#create_radixtree_uri_router() 函数
```
    -- 遍历 etcd 中所有的路由
    for _, route in ipairs(routes) do
        if type(route) == "table" then
            -- 根据 route 的 status 属性来判断是否创建路由，即路由的启用禁用
            local status = core.table.try_read_attr(route, "value", "status")
            -- check the status
            if status and status == 0 then
                goto CONTINUE
            end

            local filter_fun, err
            -- route.value.filter_func 是用户自定义的过滤函数。可以使用它来实现特殊场景的匹配要求实现。该函数默认接受一个名为 vars 的输入参数，可以用它来获取 Nginx 变量。
            if route.value.filter_func then
                filter_fun, err = loadstring(
                                        "return " .. route.value.filter_func,
                                        "router#" .. route.value.id)
                if not filter_fun then
                    core.log.error("failed to load filter function: ", err,
                                   " route id: ", route.value.id)
                    goto CONTINUE
                end
                -- 在函数名的后面加上括号，把 filter_fun 执行起来
                -- 将 filter_fun() 执行结果重新赋值给变量 filter_fun
                filter_fun = filter_fun()
            end

            core.log.info("insert uri route: ",
                          core.json.delay_encode(route.value, true))
            -- 向 uri_routes 表中插入一条新建的 route
            core.table.insert(uri_routes, {
                paths = route.value.uris or route.value.uri,
                methods = route.value.methods,
                priority = route.value.priority,
                hosts = route.value.hosts or route.value.host,
                remote_addrs = route.value.remote_addrs
                               or route.value.remote_addr,
                vars = route.value.vars,
                filter_fun = filter_fun,
                -- 路由匹配成功之后的回调函数
                handler = function (api_ctx, match_opts)
                    api_ctx.matched_params = nil
                    api_ctx.matched_route = route
                    api_ctx.curr_req_matched = match_opts.matched
                end
            })

            ::CONTINUE::
        end
    end
```
这里有个弊端，由于前面路由匹配那边是根据 worker 级别的缓存版本号和 etcd 中最新的版本号作对比，来判断是否需要更新路由，但是并没有记录是哪些路由需要更新，因此 etcd 中任何一条路由的更新都会引发 APISIX 中全部路由的更新。在路由数量级很大的情况下，频繁更新少量路由会损耗性能，CPU 被消耗在很多不必要的计算上。

## filter_func 用户自定义过滤函数
route.value.filter_func 是用户自定义的过滤函数，举例，如果用户配置的 filter_func 是如下一段 string 类型的 lua 代码
```
function(vars)
    ngx.log(ngx.WARN, 'filter_fun: 2')
    return vars['arg_a1'] == 'a1' and vars['arg_a2'] == 'a2'
end
```
用 loadstring() 函数来 "eval" 进 Lua VM，即热装载代码
```
            if route.value.filter_func then
                filter_fun, err = loadstring(
                                        "return " .. route.value.filter_func,
                                        "router#" .. route.value.id)
```
经过如上的操作，实际上 filter_fun 前面加上了一个 return，因此此刻 filter_fun 是一个函数引用，其函数完整如下
```
return function(vars)
    ngx.log(ngx.WARN, 'filter_fun: 2')
    return vars['arg_a1'] == 'a1' and vars['arg_a2'] == 'a2'
end
```
下面通过 filter_fun() 在函数名的后面加上括号的方式，执行 filter_fun() 函数，执行的结果就是 return 一个匿名函数，即用户配置的自定义函数。然后将这个匿名函数指针重新赋值给 filter_fun 这个变量。

为什么要多这样的一步呢？可以直接把用户配置的 string 类型的 lua 代码 通过 loadstring() 函数热装载进来的。带着这个问题继续探究。

在[官网](https://www.lua.org/pil/8.html)找到了关于 loadstring 函数的定义，最下面有关于添加 return 的解释。

loadstring最典型的用途是运行外部代码，也就是来自程序之外的代码。例如，你可能想绘制一个由用户定义的函数；用户输入函数代码，然后你使用 loadstring 来对它求值。注意，loadstring接受的入参的是一个程序段，也就是语句。如果你想对一个表达式进行求值，你必须在它的前面加上return，这样你就会得到一个返回给定表达式值的语句。

表达式（expression）：常量表达式，算术表达式，关系表达式，逻辑表达式，连接表达式，Vararg 表达式，函数调用表达式，函数声明， table 构造表达式等等；

函数定义是一种可执行的表达式，它返回的结果是 function 类型的值。

程序段（chunk）：Lua 语言执行的每一段代码（例如，一个文件或交互模式下的一行）成为一个程序段（chunk），即一组命令或表达式组成的序列。程序段即可以简单到只由一句表达式构成，也可以由多句表达式和函数定义（实际上是赋值表达式）组成。

语句（statement）：包括赋值语句，控制结构等。

（更多参考https://juejin.cn/post/6844903511990222855#heading-10%EF%BC%8Chttps://www.kancloud.cn/digest/lua-programming/204455%EF%BC%89

我会这样理解表达式和语句的区别，表达式是可以被求值的代码，而语句是一段可执行的代码。因为表达式可以被求值，所以它可以写在赋值语句等号的右侧，而语句不一定有值。表达式一定是语句，语句不一定是表达式。

结合上面的来解释，用户输入的函数定义表达式，是可以被求值的，

根据上面的定义，filter_fun 这个变量本身是属于用户输入的一段 string 类型的 lua code，是一个函数定义表达式，也是表达式的一种。loadstring 函数只接受程序段，也就是语句，所以需要在这个函数定义前面加上 return，把可执行表达式变成一段可执行语句，赋值给 filter_fun。而在后面的赋值语句 filter_fun = filter_fun() 中，先对等号右边的语句进行求职计算，得到函数定义，将可执行的表达式（函数定义）重新赋值给 filter_fun。

绕了这么一圈，就是因为 loadstring 接受的入参的是一个程序段。

关于 loadstring 函数的第二个入参，在代码中是 "router#" .. route.value.id，根据 loadstring 函数的定义：loadstring (string [, chunkname])，第二个函数是 chunkname，就是程序段的名字，最直接的用处就是发生错误的时候，错误信息中携带 chunkname，比如这样
```
[string "router#2"]:1: '<name>' expected near '(' route id: 2
```
如果没有传入 chunkname 参数，则错误信息直接使用程序段的 string 字符串（截取从开始位置到换行符）
```
[string "function(vars)..."]:1: '<name>' expected near '(' route id: 2
```
filter_func 函数执行时机
```
    if with_parameter then
        -- 调用 radixtree 创建路由
        return radixtree.new(uri_routes)
    else
        return router.new(uri_routes)
    end
```
with_parameter 是一个bool 值，用来指示创建的路由中是否是 path 中携带请求参数的那种路由（适配 restful 风格的请求）。

用户自定义的 filter_func 的执行时机是在路由匹配的时候

/apisix/deps/share/lua/5.1/resty/radixtree.lua#match_route_opts
```
    -- 如果指定了自定义的 filter_fun，则执行
    if route.filter_fun then
        local fn = route.filter_fun

        local ok
        if args then
            -- now we can safely clear the self.args
            local args_len = args[0]
            args[0] = nil
            -- opts.vars 即请求的参数 table
            -- unpack 将数组形式的 args 拆开，返回多个值
            -- 备注 unpack 是 NYI 原语，即 Not Yet Implemented，JIT 编译器不支持编译这个原语，会退回到解释器模式
            ok = fn(opts.vars or ngx_var, opts, unpack(args, 1, args_len))
        else
            ok = fn(opts.vars or ngx_var, opts)
        end

        if not ok then
            return false
        end
    end

    return true
```
opts.vars 即上面提到过的 t 表的数据，当 key 在元表的 __index 中找不到的时候，会去 Nginx 的变量中去获取 key 的值。比如 get 请求的参数等。

这段比较简单，就是执行用户自定的过滤函数 filter_fun，传入定义好的参数 vars，其中包括 Nginx 的变量和一些 APISIX 自己的变量。

radixtree.new(uri_routes) 创建路由
真正创建路由的是 radixtree.new(uri_routes)，返回创建好的 radixtree 对象，后面的请求 match 和 dispatch 都使用这个新建 radixtree 对象。这里会有个问题，原来的 radixtree 对象去哪儿了？肯定是被删除了，但是不知道在什么时候删除的。

探究了一下 lua-resty-radixtree 源码
```
local mt = { __index = _M, __gc = gc_free }
……

-- only work under lua51 or luajit
local function setmt__gc(t, mt)
    -- 创建一个空的带 metatable 的 userdata
    local prox = newproxy(true)
    -- 获取创建出来的 userdata 的 metatable，指定 __gc 函数
    -- mt.__gc --> gc_free --> free
    getmetatable(prox).__gc = function() mt.__gc(t) end
    -- 在 t 对象上保持唯一的引用指向 userdata
    -- 当 t 的 prox 被回收的时候，会调用到 t 的 free 函数
    t[prox] = true
    -- 设置 t 对象的元表
    return setmetatable(t, mt)
end

local function gc_free(self)
    -- if ngx.worker.exiting() then
    --     return
    -- end

    self:free()
end

……

function _M.free(self)
    local it = self.tree_it
    if it then
        radix.radix_tree_stop(it)
        ffi.C.free(it)
        self.tree_it = nil
    end

    if self.tree then
        radix.radix_tree_destroy(self.tree)
        self.tree = nil
    end

    return
```
在 Lua5.1 中有 __gc 函数，以下摘自官方文档

使用C API，你可以为 userdata 设置垃圾收集器元方法……在 metatables 中带有 __gc 的垃圾 userdata 不会立即被垃圾收集器收集。相反，Lua会把它们放在一个列表中。在收集之后，Lua 对该列表中的每个用户数据都做了相当于下面的函数。
```
     function gc_event (udata)
       local h = metatable(udata).__gc
       if h then
         h(udata)
       end
     end
```
参考：http://www.lua.org/manual/5.1/manual.html#2.10.1

Lua5.1 和 LuaJIT 的 table 是没有 gc 函数的，但是 userdata 是可以指定 gc 函数的。

也就是说，Lua5.1 和 LuaJIT的 userdata 可以给其 metatable 增加一个 __gc 域，指定一个函数，该函数将会在 userdata 被回收时调用，这个 __gc 域只能用在 userdata 中，table 不支持。

userdata 一般是在 C 里面创建的数据结构，只能通过 C API 来操作。理论上 Lua 是不支持的，但是作者增加了一个隐藏的非公开测试函数 newproxy 用于创建一个空的 userdata，参数可以选择是否带 metatable。

使用它就也可以创建一个空的 userdata 并指定 __gc 操作，在对象上保持一个唯一引用到该 userdata，当 table 被销毁前，table 所唯一引用的 userdata 也会销毁，而销毁 userdata 会先调用其 metatable 中的 __gc 域所指向的 gc 函数 。

## step4: 路由匹配
路由匹配的代码在 apisix.http.route.lua，调用 radixtree 的 dispatch 函数来执行路由匹配。
```
function _M.match_uri(uri_router, match_opts, api_ctx)
    -- 参数处理
    core.table.clear(match_opts)
    match_opts.method = api_ctx.var.request_method
    match_opts.host = api_ctx.var.host
    match_opts.remote_addr = api_ctx.var.remote_addr
    match_opts.vars = api_ctx.var
    match_opts.matched = core.tablepool.fetch("matched_route_record", 0, 4)
    -- 调用 radixtree 的 dispatch 函数
    local ok = uri_router:dispatch(api_ctx.var.uri, match_opts, api_ctx, match_opts)
    return ok
end
```

在 dispatch 函数的末尾，有这样一段代码
```
    local handler = route.handler
    if not handler or type(handler) ~= "function" then
        return nil, "missing handler"
    end

    handler(...)
```
handler 相当于路由的回调函数，是路由的一个属性，创建路由的时候就需要设置。当路由匹配成功之后，会执行这个回调函数。

回调函数上面创建路由的时候已经有了，如下
```
               -- 这个匿名函数的入参就是上面调用 dispatch 函数的后两个参数
               handler = function (api_ctx, match_opts)
                    -- 清空传入的匹配参数
                    api_ctx.matched_params = nil
                    -- 记录匹配的路由信息，route 是用户创建的路由的信息
                    api_ctx.matched_route = route
                    -- 匹配的路由参数，match_opts.matched 是在匹配过程中记录的匹配信息，
                    -- 比如 _path，_host
                    api_ctx.curr_req_matched = match_opts.matched
                end
```
至此，路由从创建，到请求匹配路由的过程结束了，如果当前请求没有匹配的路由，则会返回 404。

匹配 service
service_fetch 查询 route 所属的 service
route 关联 service 的函数调用如下
```
-- apisix.init.lua#http_access_phase()
local service = service_fetch(route.value.service_id)

-- apisix.http.service.lua
function _M.get(service_id)
    return services:get(service_id)
end

-- apisix.core.config_etcd.lua
function _M.get(self, key)
    if not self.values_hash then
        return
    end

    local arr_idx = self.values_hash[tostring(key)]
    if not arr_idx then
        return nil
    end
    
    return self.values[arr_idx]
end
```
这里用到了两个 table 来实现检索 service 信息，values_hash 和 values

values_hash 是一个 hash 类型的 table，demo 数据如下
```
{
  ["201"] = 1
}
```
“201” 是用户定义的 service 的key，对应的 value 1 是这个 key 对应的 value 在 values 中的数组下标。

values 是一个 array 类型的 table，demo数据如下
```
{ <1>{
    clean_handlers = {},
    createdIndex = 6845,
    has_domain = false,
    key = "/apisix/services/201",
    modifiedIndex = 6845,
    value = {
      create_time = 1613751330,
      enable_websocket = true,
      id = "201",
      plugins = {
        ["limit-count"] = {
          count = 20,
          key = "remote_addr",
          policy = "local",
          rejected_code = 503,
          time_window = 60
        }
      },
      update_time = 1613751330,
      upstream = {
        hash_on = "vars",
        nodes = { {
            host = "127.0.0.1",
            port = 1980,
            weight = 1
          } },
        parent = <table 1>,
        pass_host = "pass",
        scheme = "http",
        type = "roundrobin"
      }
    }
  } }
```
这里会有一个疑问，为什么要用这两个 table 来维护用户定义的 key 和 这个 key 经过处理得到的 value（在etcd中存储的值）呢？直接一个 hash 类型的 table 也可以维护起来。

首先这个数据结构的原始结构就应该是 hash 类型，用户定义好 key 和 value。这里加上了array 来存储 value 部分，从时间复杂度上来说，hash 和 array 的查找效率是 O(1) 的，所以不是为了加速查询。

在 Lua 中，一个 table 分为 array 段和 hash 段。而 table 的 key 可以由用户指定，也可以由 APISIX 自己生成的，用户指定的 key 有可能是1，2，3 这样的数字 key，数字key 一般放在 array 段中，而 APISIX 自动创建的 key 实际上就是 etcd 的 revision（被转化成 string 类型）。
```
    -- 此段代码位于 apisix.core.etcd#push()     
    -- Create a new revision and use it as the id.
    -- It will be better if we use snowflake algorithm like manager-api,
    -- but we haven't found a good library. It costs too much to write
    -- our own one as the admin-api will be replaced by manager-api finally.
    local res, err = set("/gen_id", 1)
    if not res then
        return nil, err
    end

    -- manually add suffix
    local index = res.body.header.revision
    index = string.format("%020d", index)

    res, err = set(key .. "/" .. index, value, ttl)
```
这样会导致 table 中既有 hash 类型的数据，也有 array 类型的数据，这种混合存储并不推荐，不便于处理，比如不好计算 table 的长度。而将 value 抽出来，根据已知的要存储的元素的数量，用 table.new(narray, nhash) 来分配确定大小的 table，由于元素的数量是已知的，所以我觉得这样的设计并不能呢个节约内存，这样设计最大的好处是避免混合 table 的出现。

merge_service_route 合并 service 和 route 的相同配置
这里要解决的问题是，如果 route 和 service 有相同的配置该如何处理？比如都配置了相同的 plugins，upstreams 等。
```
function _M.merge_service_route(service_conf, route_conf)
    core.log.info("service conf: ", core.json.delay_encode(service_conf, true))
    core.log.info("  route conf: ", core.json.delay_encode(route_conf, true))

    local route_service_key = route_conf.value.id .. "#"
        .. route_conf.modifiedIndex .. "#" .. service_conf.modifiedIndex
    return merged_route(route_service_key, service_conf,
                        merge_service_route,
                        service_conf, route_conf)
end
```
```
local function merge_service_route(service_conf, route_conf)
    local new_conf = core.table.deepcopy(service_conf)
    new_conf.value.service_id = new_conf.value.id
    new_conf.value.id = route_conf.value.id
    new_conf.modifiedIndex = route_conf.modifiedIndex

    if route_conf.value.plugins then
        for name, conf in pairs(route_conf.value.plugins) do
            if not new_conf.value.plugins then
                new_conf.value.plugins = {}
            end
            -- new_conf.value.plugins --> service 上的 plugins 配置
            -- conf --> route 上 plugins 配置 
            -- [name] 名称相同的配置，即同一个 plugin 的不同实例
            -- 把 service 上的 plugins 配置替换成 route 上同名 plugins 的配置
            new_conf.value.plugins[name] = conf
        end
    end

    local route_upstream = route_conf.value.upstream
    if route_upstream then
        -- route 的 upstream 覆盖 service 的 upstream
        new_conf.value.upstream = route_upstream
        -- when route's upstream override service's upstream,
        -- the upstream.parent still point to the route
        new_conf.value.upstream_id = nil
        new_conf.has_domain = route_conf.has_domain
    end

    if route_conf.value.upstream_id then
        -- route 的 upstream_id 覆盖 service 的 upstream_id
        new_conf.value.upstream_id = route_conf.value.upstream_id
        new_conf.has_domain = route_conf.has_domain
    end

    -- core.log.info("merged conf : ", core.json.delay_encode(new_conf))
    return new_conf
end
```
总结起来如下：当 route 和 service 拥有相同类型的配置时，比如同名的 plugins，upstream 或 upstream_id，route 的配置覆盖 service 的配置。

如果 route 没有，而 service 存在的配置，则不修改。

parse_domain_in_up 域名解析
ipmatcher.parse_ipv4：校验 ip 还是域名
匹配完 service 后，就是匹配 upstream 了，过程与 匹配 service 类似，其中涉及到域名解析。

下面详细分析以下域名解析的过程，其中还会涉及到一个很大的bug——k8s的内部短域名不能被解析的问题。
```
local function parse_domain_for_nodes(nodes)
    local new_nodes = core.table.new(#nodes, 0)
    for _, node in ipairs(nodes) do
        local host = node.host
        -- 如果不是 ipv4 或 ipv6 的 ip，则调用域名解析
        if not ipmatcher.parse_ipv4(host) and
                not ipmatcher.parse_ipv6(host) then
            local ip, err = parse_domain(host)
            if ip then
                local new_node = core.table.clone(node)
                new_node.host = ip
                new_node.domain = host
                core.table.insert(new_nodes, new_node)
            end

            if err then
                core.log.error("dns resolver domain: ", host, " error: ", err)
            end
        else
            core.table.insert(new_nodes, node)
        end
    end
    return new_nodes
end

local function parse_domain_in_up(up)
    local nodes = up.value.nodes
    -- 解析 nodes 中的域名
    local new_nodes, err = parse_domain_for_nodes(nodes)
    if not new_nodes then
        return nil, err
    end

    local old_dns_value = up.dns_value and up.dns_value.nodes
    local ok = upstream_util.compare_upstream_node(old_dns_value, new_nodes)
    if ok then
        return up
    end

    local up_new = core.table.clone(up)
    up_new.modifiedIndex = up.modifiedIndex .. "#" .. ngx_now()
    up_new.dns_value = core.table.clone(up.value)
    up_new.dns_value.nodes = new_nodes
    core.log.info("resolve upstream which contain domain: ",
                  core.json.delay_encode(up_new))
    return up_new
end
```
这里主要是区分 upstream 的 nodes 中存储的是否是域名，其中用到了 ipmatcher 这个库，下面看一下 parse_ipv4 这个函数，这个函数试图将IPv4地址解析为主机字节序FFI uint32_t类型的整数。


```
local parse_ipv4
do  
    -- 调用 ffi.new 分配内存， ffi.new 返回的是一个 cdata，这部分内存由 LuaJIT 管理
    local inet = ffi_new("unsigned int [1]")

    function parse_ipv4(ip)
        if not ip then
            return false
        end

        if C.inet_pton(AF_INET, ip, inet) ~= 1 then
            return false
        end

        return C.ntohl(inet[0])
    end
end
_M.parse_ipv4 = parse_ipv4
```
概念1：主机字节序，即 CPU 存储数据采用的字节顺序，不同 CPU 采用的字节顺序是不同的，主要分为两派。PowerPC系列，采用 big endian （大端）方式存储数据。x86与x86_64系列，采用 little endian （小端）方式存储数据。

参考：https://blog.csdn.net/K346K346/article/details/79053136

举个例子，从主机 a 到 主机 b 的通信

a的固有数据存储 --> 标准化 --> 转化成b的固有格式

不同体系结构的机器之间不能直接通信，可能会存在不是同一种 CPU 架构，所以要由转换成一种约定标准化的顺序的过程：

a 或者 b 的固有数据存储个是就是自己的主机字节序，标准化过程就是为那个罗字节序（big endian 字节序），所以从 a 到 b 的数据传输换个说法就是

a的主机字节序 --> 网络字节序 --> b的主机字节序

参考：https://blog.csdn.net/msdnwolaile/article/details/50727653

总之这个函数就是返回一个给定 ip 的主机字节序号，如果给定的不是 ip，则直接返回 false。在这里使用主要是用了其检测是否是 ip 的能力，而没有用到转换主机字节序的功能。

这里涉及到 FFI 相关的东西。FFI 全称是 Foreign Function Interface，通常来说，指其他语言调用 C 的函数。
```
-- 使用 ffi 库
local ffi         = require "ffi"
-- ffi.new 开辟空间，第一个参数为 ctype 对象，ctype 对象最好通过 ctype = ffi.typeof(ct) 构建
-- ctype 和 cdate 都是 Lua 里面的概念，前者存储这类型信息，后者存储着值。ffi.typeof 返回一个 cdata，这个 cdata 里面存储着一个整数 ID，LuaJIT 会通过这个 CType ID 查找实际的 CType 类型。ctype 只存在于 LuaJIT 内部实现代码中，不像 cdata 能在 Lua 代码里面访问。
-- ffi.new 分配的 cdata 对象指向的内存块是由垃圾回收器 LuaJIT GC 自动管理的，所以不需要用户去释放内存。
local ffi_new     = ffi.new
local ffi_copy    = ffi.copy
-- ffi.C.call_C_func 访问 mkdir 这种系统自带的，出现在 libc 里面的函数，加载 call_C_func 这个符号。（在编译模式下，LuaJIT 直接调用对应的 C 函数地址）
local C           = ffi.C

    -- 调用 ffi.new 分配内存， ffi.new 返回的是一个 cdata，这部分内存由 LuaJIT 管理
    local inet = ffi_new("unsigned int [1]")
……
        -- 如上所述，加载 inet_pton 这个 C 的函数
        if C.inet_pton(AF_INET, ip, inet) ~= 1 then
            return false
        end

```
参考：https://moonbingbing.gitbooks.io/openresty-best-practices/content/lua/FFI.html

https://segmentfault.com/a/1190000015802547

https://segmentfault.com/a/1190000016149595

dns_parse：域名解析
```
local function parse_domain(host)
    -- 调用 apisix.core.utils 模块的域名解析
    local ip_info, err = core.utils.dns_parse(host)
    if not ip_info then
        core.log.error("failed to parse domain: ", host, ", error: ",err)
        return nil, err
    end

    core.log.info("parse addr: ", core.json.delay_encode(ip_info))
    core.log.info("resolver: ", core.json.delay_encode(dns_resolver))
    core.log.info("host: ", host)
    if ip_info.address then
        core.log.info("dns resolver domain: ", host, " to ", ip_info.address)
        return ip_info.address
    else
        return nil, "failed to parse domain"
    end
end

-- apisix.core.utils#dns_parse
local function dns_parse(domain)
    if dns_resolvers ~= current_inited_resolvers then
        local opts = {
            ipv6 = true,
            nameservers = table.clone(dns_resolvers),
            retrans = 5,  -- 5 retransmissions on receive timeout
            timeout = 2000,  -- 2 sec
        }
        -- 初始化 dns client ，dns_client 是模块级变量，只需要初始化一次
        -- 这个初始化可以调用多次，再次调用时会清楚缓存
        local ok, err = dns_client.init(opts)
        if not ok then
            return nil, "failed to init the dns client: " .. err
        end

        current_inited_resolvers = dns_resolvers
    end  
    ……
end
```
dns_resolvers：默认的域名解析地址
先来看看 dns_resolvers 这个变量是哪儿来的。首先这个值来源于 服务器上的 /etc/resolv.conf 文件，比如在我的服务器上，/etc/resolv.conf配置如下
```
nameserver 8.8.8.8
```
在 config-default.yaml 文件中有提到过，如果没有对此配置项进行配置，则默认读取 /etc/resolv.conf
```
  # dns_resolver:                 # If not set, read from `/etc/resolv.conf`
  #  - 1.1.1.1
  #  - 8.8.8.8
```
对应的读取该配置文件的代码在 apisix.cli.ops.lua#init 函数中
```
   -- 如果未配置，则默认读取 "/etc/resolv.conf" 
   if not dns_resolver or #dns_resolver == 0 then
        local dns_addrs, err = local_dns_resolver("/etc/resolv.conf")
        if not dns_addrs then
            util.die("failed to import local DNS: ", err, "\n")
        end

        if #dns_addrs == 0 then
            util.die("local DNS is empty\n")
        end

        sys_conf["dns_resolver"] = dns_addrs
    end
```
这个过程发生在 apisix 的启动时的脚本命令中，在 apisix 最终调用 openresty 启动命令之前。属于环境变量准备的过程。

下一步，sys_conf["dns_resolver"] 存储的这个变量会在生成 nginx.conf 配置文件的时候被读取，nginx.conf 配置文件是由 ngx_tpl 模板结合环境变量所生成的，ngx_tpl 模板代码中读取该环境变量的代码如下
```
    init_by_lua_block {
        require "resty.core"
        apisix = require("apisix")

        local dns_resolver = { {% for _, dns_addr in ipairs(dns_resolver or {}) do %} "{*dns_addr*}", {% end %} }
        local args = {
            dns_resolver = dns_resolver,
        }
        apisix.http_init(args)
    }
```
生成的 nginx.conf 中对应的配置如下
```
    init_by_lua_block {
        require "resty.core"
        apisix = require("apisix")

        local dns_resolver = { "8.8.8.8", }
        local args = {
            dns_resolver = dns_resolver,
        }
        apisix.http_init(args)
    }
```
可以看到，在 init_by_lua_block 阶段，拿到 dns_resolver 这个环境变量后，在调用 apisix.http_init 函数时作为参数传递。

在 apisix 中，函数调用如下
```
-- /apisix/init.lua
local function parse_args(args)
    dns_resolver = args and args["dns_resolver"]
    core.utils.set_resolver(dns_resolver)
end

function _M.http_init(args)
    parse_args(args)
end

-- /apisix/core/utils.luq
local dns_resolvers
function _M.set_resolver(resolvers)
    dns_resolvers = resolvers
end
```
经过这一串调用，在 master 进程的 init 阶段，即读取了服务器上 /etc/resolv.conf 这个配置，获取了运行 apisix 那台服务器上配置的域名解析服务器的 ip。

而 current_inited_resolvers 这个变量是一个模块级变量，作为 dns_resolvers 配置的 worker 级别的缓存。

继续看 dns_parse 函数，真正完成域名解析。

在之前的 APISIX 版本中，使用的是 lua-resty-dns 这个 openresty 的核心类库。调用过程如下
```
-- /apisix/core/utils.lua
local function dns_parse(domain, resolvers)
    resolvers = resolvers or _M.resolvers
    -- 初始化调用核心类库 lua-resty-dns
    local r, err = resolver:new{
        nameservers = table.clone(resolvers),
        retrans = 5,  -- 5 retransmissions on receive timeout
        timeout = 2000,  -- 2 sec
    }

    if not r then
        return nil, "failed to instantiate the resolver: " .. err
    end
    -- 查询域名 
    local answers, err = r:query(domain, nil, {})
    if not answers then
        return nil, "failed to query the DNS server: " .. err
    end
    ……
    -- 递归解析
    return dns_parse(answer.cname, resolvers)
end

-- path/openresty/lualib/resty/dns/resolver.lua
function _M.query(self, qname, opts, tries)
    -- 获取 socket 连接
    local socks = self.socks
    if not socks then
        return nil, "not initialized"
    end

    local id = _gen_id(self)
    
    -- 构建查询请求
    local query, err = _build_request(qname, id, self.no_recurse, opts)
    if not query then
        return nil, errlua_code_cache
    end
    ……

    for i = 1, retrans do
        local sock = pick_sock(self, socks)

        local ok
        -- 真正地发送socket 请求的地方
        ok, err = sock:send(query)
        if not ok then
            local server = _get_cur_server(self)
            err = "failed to send request to UDP server "
                .. concat(server, ":") .. ": " .. err

        else
            local buf

            for _ = 1, 128 do
                -- 读取 socket 输出流 buffer
                buf, err = sock:receive(4096)

                ……

                if buf then
                    local answers
                    -- 解析 answers
                    answers, err = parse_response(buf, id, opts)
                    ……
    end

    return nil, err, tries
end
```
原来版本的域名查询逻辑比较简单，拿着域名去请求域名服务器，获服务器响应中的 ip。

但是这有个问题，容器内域名解析的过程不仅仅用域名去访问域名服务器进行查询这么简单。比如我在 k8s 中部署的 APISIX 的 /etc/resolver.conf 文件配置如下：
```
nameserver 10.0.0.10
search foo.svc.cluster.local. svc.cluster.local. cluster.local
options ndots:5 
```
容器内部的DNS解析由/etc/resolv.conf配置文件主导。默认Kubernetes dnsPolicy是ClusterFirst，这意味着任何带有search域名后缀的DNS查询将被路由到集群内kube-dnspod上去解析。我上面的resolv.conf 有三个指令：

nameserver：域名解析服务器 ip
search：查询主机名的搜索列表
ndots：设置在进行初始绝对查询之前，名称中必须出现的点的数量的阈值
此配置的有趣部分是本search地域和ndots:5设置如何一起使用。为了理解它，我们需要了解DNS解析对于非完全限定名称的工作方式。 什么是标准名称？ 完全限定名称是不会对其进行本地搜索的名称，并且在解析过程中，该名称将被视为绝对名称。按照约定，如果以句号（.）结尾，则DNS软件认为名称是完全合格的，否则，则认为该名称不是完全合格的。就是 google.com.是完全合格的，google.com不是。 如何执行非完全合格的名称解析？ 当应用程序连接到按名称指定的远程主机时，通常通过syscall来执行DNS解析，例如getaddrinfo()。如果名称不完全限定（不以结尾.），系统调用将首先尝试将名称解析为绝对名称，还是先通过本地搜索域？这取决于ndots选项。

这意味着，如果ndots将设置为5，并且名称中包含少于5个点，则syscall会尝试依次通过所有本地搜索域来依次解决该问题，并且在没有成功的情况下，仅在最后将其解析为绝对名称。

在 APISIX 最新的代码中，使用了 [lua-resty-dns-client](https://kong.github.io/lua-resty-dns-client/modules/resty.dns.client.html) 这个类库作为 DNS 解析工具，这个类库基本遵循了上述的解析方式。调用处代码如下：
```
-- apisix.core.utils#dns_parse
local dns_client     = require("resty.dns.client")

local function dns_parse(domain)
    ……
    log.info("dns resolve ", domain)

    -- this function will dereference the CNAME records
    local answers, err = dns_client.resolve(domain)
    if not answers then
        return nil, "failed to query the DNS server: " .. err
    end

    if answers.errcode then
        return nil, "server returned error code: " .. answers.errcode
                    .. ": " .. answers.errstr
    end

    local idx = math.random(1, #answers)
    local answer = answers[idx]
    local dns_type = answer.type
    -- TODO: support AAAA & SRV
    if dns_type == dns_client.TYPE_A then
        return table.deepcopy(answer)
    end

    return nil, "unsupport DNS answer"
end
```
当查询的域名中少于 5 个（.）的时候，如果直接用用户指定的域名查询不到结果，就会依次把 search 列表中的域名后缀拼接在用户指定的域名后面，但是 search 列表中的域名后缀最后是有（.）的，是完全限定名称。但是 k8s 的域名服务器返回的结果中，完全限定名称的末尾是不包含（.）的。

举个例子，当我的查询域名是 foo-nj-dev.foo 的时候，经过拼接 search 域名后缀，可以得到 foo-nj-dev.foo.svc.cluster.local. 这是一个 k8s 的FQDN格式（完全限定域名），用这个域名去查询 k8s 域名服务器，可以查询到结果，但是这个结果是 foo-nj-dev.foo.svc.cluster.local，比查询的域名在末尾少一个（.）。

按道理说，这个解析的结果是可以用的，这个结果就是正确的查询结果，但是这个 lua-resty-dns-client 在解析 k8s 域名服务器查询结果的时候，/resty/dns/client.lua#parseAnswer() 有下面这样的判断
```
  -- 如果查询的域名类型和响应的域名类型不一致，或者查询的域名和响应的域名不一致，则删除响应的记录
  if (answer.type ~= qtype) or (answer.name ~= qname) then
      local key = answer.type..":"..answer.name
      try_status(try_list, key .. " removed")
      local lst = others[key]
      if not lst then
        lst = {}
        others[key] = lst
      end
      table_insert(lst, 1, answer)  -- pos 1: preserve order
      table_remove(answers, i)
    end
  end
```
由于查询的域名比响应的域名在末尾多了一个（.），导致 if 判断的条件 answer.name ~= qname 生效，进入if后，相当于本次查询是失败的，先记录一下尝试查询的记录，所以能看到两次 removed 记录，然后从 answers中把这条域名记录删除，即table_remove(answers, i)这段代码，这就是导致为什么出现 101 empty record received 的真正原因，明明已经获得了 DNS 服务器响应的域名记录，但是由于查询的域名和服务器响应的域名不一致，所以删掉 DNS 服务器响应的域名记录，然后方法返回，在上层的 /resty/dns/client.lua 中的 resolve() 函数中判断DNS服务器响应的域名记录数量，如下代码
```
local clientErrors = {     -- client specific errors
    [100] = "cache only lookup failed",
    [101] = "empty record received",
}
elseif #records == 0 then
            -- empty: fall through to the next entry in our search sequence
            err = ("dns client error: %s %s"):format(101, clientErrors[101])
            -- luacheck: push no unused
            records = nil
```
由于DNS响应的 answers 中域名记录在 parseAnswer() 中删除了，当然是0条记录了，都在所以 records == 0，触发异常，继续往上抛异常，empty record received，一直把err抛到最上层，最上层根据err报错。

额外提一点，在 k8s 中使用是，upstream 配置长域名是有好处的，不走 search 查询逻辑，避免进行多次DNS域名查询。