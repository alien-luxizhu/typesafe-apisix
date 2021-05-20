--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
local require       = require
require("apisix.patch").patch()
local core          = require("apisix.core")
local plugin        = require("apisix.plugin")
local plugin_config = require("apisix.plugin_config")
local script        = require("apisix.script")
local service_fetch = require("apisix.http.service").get
local admin_init    = require("apisix.admin.init")
local get_var       = require("resty.ngxvar").fetch
local router        = require("apisix.router")
local set_upstream  = require("apisix.upstream").set_by_route
local upstream_util = require("apisix.utils.upstream")
local ctxdump       = require("resty.ctxdump")
local ipmatcher     = require("resty.ipmatcher")
local ngx           = ngx
local ngx_version   = ngx.config.nginx_version
local get_method    = ngx.req.get_method
local ngx_exit      = ngx.exit
local math          = math
local error         = error
local ipairs        = ipairs
local tostring      = tostring
local ngx_now       = ngx.now
local ngx_var       = ngx.var
local str_byte      = string.byte
local str_sub       = string.sub
local tonumber      = tonumber
local control_api_router
if ngx.config.subsystem == "http" then
    control_api_router = require("apisix.control.router")
end
local load_balancer
local local_conf
local dns_resolver
local ver_header    = "APISIX/" .. core.version.VERSION


local function parse_args(args)
    dns_resolver = args and args["dns_resolver"]
    core.utils.set_resolver(dns_resolver)
    core.log.info("dns resolver", core.json.delay_encode(dns_resolver, true))
end


local _M = {version = 0.4}


function _M.http_init(args)
    require("resty.core")

    if require("ffi").os == "Linux" then
        require("ngx.re").opt("jit_stack_size", 200 * 1024)
    end

    require("jit.opt").start("minstitch=2", "maxtrace=4000",
                             "maxrecord=8000", "sizemcode=64",
                             "maxmcode=4000", "maxirconst=1000")

--  dns 预处理
    parse_args(args)

--  apisix.uid生成    
    core.id.init()

    local process = require("ngx.process")
    local ok, err = process.enable_privileged_agent()
    if not ok then
        core.log.error("failed to enable privileged_agent: ", err)
    end

    if core.config.init then
        local ok, err = core.config.init()
        if not ok then
            core.log.error("failed to load the configuration: ", err)
        end
    end
end


function _M.http_init_worker()
    local seed, err = core.utils.get_seed_from_urandom()
    if not seed then
        core.log.warn('failed to get seed from urandom: ', err)
        seed = ngx_now() * 1000 + ngx.worker.pid()
    end
    math.randomseed(seed)
    -- for testing only
    core.log.info("random test in [1, 10000]: ", math.random(1, 10000))

    local we = require("resty.worker.events")
    local ok, err = we.configure({shm = "worker-events", interval = 0.1})
    if not ok then
        error("failed to init worker event: " .. err)
    end

    -- 服务发现模块暂时用不到
    --[[
    local discovery = require("apisix.discovery.init").discovery
    if discovery and discovery.init_worker then
        discovery.init_worker()
    end
    --]]

    -- 先准备好函数，供后边http_balancer_phase阶段使用
    require("apisix.balancer").init_worker()
    load_balancer = require("apisix.balancer").run


    -- 管理端口，这部分不用了，前端直接访问etcd
    -- require("apisix.admin.init").init_worker()

    -- 定时器，给一些需要定时执行的插件用的，log-rotate、server-info、error-log-logger
    require("apisix.timers").init_worker()

    -- load 插件，plugin_config
    plugin.init_worker()

    -- 从etcd里获取router信息，radixtree_sni这个貌似没用了,global_rules我们也用不到
    router.http_init_worker()


    -- service和consumer暂时不用
    require("apisix.http.service").init_worker()


    plugin_config.init_worker()

    require("apisix.consumer").init_worker()

    -- 如果是应急状态，定时读本地文件。
    -- 这种状态也可以配合其他的配置管理下发工具定时更新，来达到管理目的
    if core.config == require("apisix.core.config_yaml") then
        core.config.init_worker()
    end

    -- require("apisix.debug").init_worker()
    -- 定时获取node节点
    require("apisix.upstream").init_worker()

    local_conf = core.config.local_conf()

    if local_conf.apisix and local_conf.apisix.enable_server_tokens == false then
        ver_header = "APISIX"
    end
end


function _M.http_ssl_phase()
    local ngx_ctx = ngx.ctx
    local api_ctx = ngx_ctx.api_ctx

    if api_ctx == nil then
        api_ctx = core.tablepool.fetch("api_ctx", 0, 32)
        ngx_ctx.api_ctx = api_ctx
    end

    local ok, err = router.router_ssl.match_and_set(api_ctx)
    if not ok then
        if err then
            core.log.error("failed to fetch ssl config: ", err)
        end
        ngx_exit(-1)
    end
end


local function parse_domain(host)
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
_M.parse_domain = parse_domain

---@param nodes { host: string, domain: string }[]
local function parse_domain_for_nodes(nodes)
    local new_nodes = core.table.new(#nodes, 0)
    for _, node in ipairs(nodes) do
        local host = node.host
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

---@param up etcd_upstream_node_t
local function parse_domain_in_up(up)
    local nodes = up.value.nodes
    local new_nodes, err = parse_domain_for_nodes(nodes)
    if not new_nodes then
        return nil, err
    end

    local ok = upstream_util.compare_upstream_node(up.dns_value, new_nodes)
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

---@param route etcd_route_node_t
local function parse_domain_in_route(route)
    local nodes = route.value.upstream.nodes
    local new_nodes, err = parse_domain_for_nodes(nodes)
    if not new_nodes then
        return nil, err
    end

    local up_conf = route.dns_value and route.dns_value.upstream
    local ok = upstream_util.compare_upstream_node(up_conf, new_nodes)
    if ok then
        return route
    end

    local route_new = core.table.clone(route)
    route_new.modifiedIndex = route.modifiedIndex .. "#" .. ngx_now()

    route_new.dns_value = core.table.deepcopy(route.value)
    route_new.dns_value.upstream.nodes = new_nodes
    core.log.info("parse route which contain domain: ",
                  core.json.delay_encode(route))
    return route_new
end

---@param api_ctx api_ctx
local function set_upstream_host(api_ctx)
    local pass_host = api_ctx.pass_host or "pass"
    if pass_host == "pass" then
        return
    end

    if pass_host == "rewrite" then
        api_ctx.var.upstream_host = api_ctx.upstream_host
        return
    end

    -- only support single node for `node` mode currently
    local host
    local up_conf = api_ctx.upstream_conf
    local nodes_count = up_conf.nodes and #up_conf.nodes or 0
    if nodes_count == 1 then
        local node = up_conf.nodes[1]
        if node.domain and #node.domain > 0 then
            host = node.domain
        else
            host = node.host
        end
    end

    if host then
        api_ctx.var.upstream_host = host
    end
end


function _M.http_access_phase()
    local ngx_ctx = ngx.ctx
    -- always fetch table from the table pool, we don't need a reused api_ctx
    ---@type api_ctx
    local api_ctx = core.tablepool.fetch("api_ctx", 0, 32)
    ngx_ctx.api_ctx = api_ctx

    core.ctx.set_vars_meta(api_ctx)
    core.log.info("http_access_phase api_ctx",
            core.json.encode(api_ctx, true))

    --[[
    {"var":{"_request":"cdata<void *>: 0x01068fa0"}}
    --]]
    local uri = api_ctx.var.uri
    if local_conf.apisix and local_conf.apisix.delete_uri_tail_slash then
        if str_byte(uri, #uri) == str_byte("/") then
            api_ctx.var.uri = str_sub(api_ctx.var.uri, 1, #uri - 1)
            core.log.info("remove the end of uri '/', current uri: ",
                          api_ctx.var.uri)
        end
    end

    if router.api.has_route_not_under_apisix() or
        core.string.has_prefix(uri, "/apisix/")
    then
        local skip = local_conf and local_conf.apisix.global_rule_skip_internal_api
        local matched = router.api.match(api_ctx, skip)
        if matched then
            return
        end
    end

    -- 请求uri 与 etcd中配置的uri 匹配
    -- 如果匹配成功，则放在api_ctx.matched_route中
    router.router_http.match(api_ctx)

    -- run global rule
    plugin.run_global_rules(api_ctx, router.global_rules, "access")

    local route = api_ctx.matched_route
    if not route then
        core.log.info("not find any matched route")
        return core.response.exit(404,
                    {error_msg = "404 Route Not Found"})
    end

    core.log.debug("matched route: ",
                  core.json.delay_encode(api_ctx.matched_route, true))
    --[[
    {
        "key": "\/apisix\/routes\/348388866928938607",
        "has_domain": false,
        "clean_handlers": {},
        "modifiedIndex": 1944,
        "createdIndex": 641,
        "orig_modifiedIndex": 1944,
        "value": {
            "priority": 0,
            "desc": "hello11111111222",
            "name": "beiji      ng",
            "vars": [
                ["http_agent", "==", "ios-5.7.0"]
            ],
            "id": "348388866928938607",
            "status": 1,
            "upstream_id": "348387005614263919",
            "methods": ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
            "uris": ["\/api\/test1"],
            "hosts": ["*.sjzqtest1.com"],
            "update_time": 1617261882,
            "create_time": 1617185546,
            "plugins": {
                "limit-count": {
                    "count": 10,
                    "policy": "local",
                    "rejected_code": 503,
                    "time_window": 10,
                    "redis_timeout": 1000,
                    "key": "remote_addr"
                }
            }
        },
        "update_count": 0
    }
    --]]
    local enable_websocket = route.value.enable_websocket

    if route.value.plugin_config_id then
        local conf = plugin_config.get(route.value.plugin_config_id)
        if not conf then
            core.log.error("failed to fetch plugin config by ",
                            "id: ", route.value.plugin_config_id)
            return core.response.exit(503)
        end

        route = plugin_config.merge(route, conf)
    end

    if route.value.service_id then
        local service = service_fetch(route.value.service_id)
        if not service then
            core.log.error("failed to fetch service configuration by ",
                           "id: ", route.value.service_id)
            return core.response.exit(404)
        end

        route = plugin.merge_service_route(service, route)
        api_ctx.matched_route = route
        api_ctx.conf_type = "route&service"
        api_ctx.conf_version = route.modifiedIndex .. "&" .. service.modifiedIndex
        api_ctx.conf_id = route.value.id .. "&" .. service.value.id
        api_ctx.service_id = service.value.id
        api_ctx.service_name = service.value.name

        if enable_websocket == nil then
            enable_websocket = service.value.enable_websocket
        end

    else
        api_ctx.conf_type = "route"
        api_ctx.conf_version = route.modifiedIndex
        api_ctx.conf_id = route.value.id
    end
    api_ctx.route_id = route.value.id
    api_ctx.route_name = route.value.name

    if route.value.script then
        script.load(route, api_ctx)
        script.run("access", api_ctx)
    else
        local plugins = plugin.filter(route)
        core.log.debug("http_access_phase plugins: ",
                core.json.delay_encode(plugins, true))

        --[[
        [{
            "priority": 1002,
            "version": 0.4,
            "access": "function: 0x7fc026fa7ff8",
            "check_schema": "function: 0x7fc026fa7d48",
            "schema": {
                "dependencies": {
                    "policy": {
                        "oneOf": [{
                            "properties": {
                                "policy": {
                                    "enum": ["local"]
                                }
                            }
                        }, {
                            "properties": {
                                "redis_host": {
                                    "type": "string",
                                    "minLength": 2
                                },
                                "redis_port": {
                                    "default": 6379,
                                    "type": "intege      r",
                                    "minimum": 1
                                },
                                "redis_password": {
                                    "type": "string",
                                    "minLength": 0
                                },
                                "redis_database": {
                                    "default": 0,
                                    "type": "i      nteger",
                                    "minimum": 0
                                },
                                "redis_timeout": {
                                    "default": 1000,
                                    "type": "integer",
                                    "minimum": 1
                                },
                                "policy": {
                                    "enum": ["redis"]
                                }
                            },
                            "required": ["redis_host"]
                        }, {
                            "properties": {
                                "redis_password": {
                                    "type": "string",
                                    "minLength": 0
                                },
                                "redi      s_cluster_nodes": {
                                    "minItems": 2,
                                    "items": {
                                        "maxLength": 100,
                                        "type": "string",
                                        "minLength": 2
                                    },
                                    "type": "array"
                                },
                                "      redis_timeout": {
                                    "default": 1000,
                                    "type": "integer",
                                    "minimum": 1
                                },
                                "policy": {
                                    "enum": ["redis-cluster"]
                                }
                            },
                            "requi      red": ["redis_cluster_nodes"]
                        }]
                    }
                },
                "required": ["count", "time_window"],
                "$comment": "this is a mark for our i      njected plugin schema",
                "type": "object",
                "properties": {
                    "count": {
                        "type": "integer",
                        "exclusiveMinimum": 0
                    },
                    "key": {
                        "default": "remote_addr",
                        "type": "string",
                        "enum": ["remote_addr", "server_addr", "http_x_real_ip", "http_x_forwarded_for", "consumer_name", "service_id"]
                    },
                    "rejected_code": {
                        "type": "integer",
                        "default": 503,
                        "minimum": 200,
                        "maximum": 599
                    },
                    "disable": {
                        "type": "boolean"
                    },
                    "time_window": {
                        "type": "integer",
                        "exclusiveMinimum": 0
                    },
                    "      policy": {
                        "default": "local",
                        "type": "string",
                        "enum": ["local", "redis", "redis-cluster"]
                    }
                }
            },
            "name": "limit-count"
        }, {
            "count": 10,
            "key": "remote_addr",
            "rejected_code": 503,
            "time_window": 10,
            "policy": "local"
        }]
        --]]

        api_ctx.plugins = plugins

        plugin.run_plugin("rewrite", plugins, api_ctx)
        if api_ctx.consumer then
            local changed
            route, changed = plugin.merge_consumer_route(
                route,
                api_ctx.consumer,
                api_ctx
            )

            core.log.info("find consumer ", api_ctx.consumer.username,
                          ", config changed: ", changed)

            if changed then
                core.table.clear(api_ctx.plugins)
                api_ctx.plugins = plugin.filter(route, api_ctx.plugins)
            end
        end
        plugin.run_plugin("access", plugins, api_ctx)
    end

    local up_id = route.value.upstream_id

    -- used for the traffic-split plugin
    if api_ctx.upstream_id then
        up_id = api_ctx.upstream_id
    end

    if up_id then
        local upstreams = core.config.fetch_created_obj("/upstreams")
        if upstreams then
            ---@type etcd_upstream_node_t
            local upstream = upstreams:get(tostring(up_id))
            if not upstream then
                core.log.error("failed to find upstream by id: " .. up_id)
                return core.response.exit(502)
            end
            core.log.debug("parsed upstream111:  ", core.json.delay_encode(upstream, true))
            if upstream.has_domain then
                local err
                upstream, err = parse_domain_in_up(upstream)
                if err then
                    core.log.error("failed to get resolved upstream: ", err)
                    return core.response.exit(500)
                end
            end

            if upstream.value.pass_host then
                api_ctx.pass_host = upstream.value.pass_host
                api_ctx.upstream_host = upstream.value.upstream_host
            end

            core.log.debug("parsed upstream222: ", core.json.delay_encode(upstream, true))
            --[[
            {
                "modifiedIndex": 610,
                "key": "\/apisix\/upstreams\/348387005614263919",
                "has_domain": false,
                "createdIndex": 610,
                "clean_handlers": {},
                "value": {
                    "type": "roundrobin",
                    "checks": {
                        "active": {
                            "healthy": {
                                "interval": 3,
                                "successes": 3,
                                "http_statuses": [200, 302]
                            },
                            "http_path": "\/api\/test1",
                            "https_verify_certificate": true,
                            "unhealthy      ": {
                                "interval": 3,
                                "http_failures": 3,
                                "tcp_failures": 2,
                                "timeouts": 3,
                                "http_statuses": [429, 404, 500, 501, 502, 503, 504, 505]
                            },
                            "timeout": 1,
                            "host": "abc.com",
                            "type": "http",
                            "concurrency": 10
                        }
                    },
                    "pass_host": "pass",
                    "create_time      ": 1617184437,
                    "name": "test",
                    "update_time": 1617184437,
                    "nodes": [{
                        "weight": 1,
                        "host": "10.101.222.24",
                        "port": 9 800
                    }, {
                        "weight": 1,
                        "host": "10.101.222.24",
                        "port": 8001
                    }],
                    "hash_on": "vars",
                    "timeout": {
                        "send": 6000,
                        "read": 600 0,
                        "connect": 6000
                    },
                    "parent": {
                        "modifiedIndex": 610,
                        "key": "\/apisix\/upstreams\/348387005614263919",
                        "has_dom      ain": false,
                        "createdIndex": 610,
                        "clean_handlers": "table: 0x7fc0179c7278",
                        "value": "table: 0x7fc022124278"
                    },
                    "scheme": "http",
                    "id": "348387005614263919"
                }
            }
            --]]

            api_ctx.matched_upstream = upstream.dns_value or upstream.value
        end

    else
        if route.has_domain then
            local err
            route, err = parse_domain_in_route(route)
            if err then
                core.log.error("failed to get resolved route: ", err)
                return core.response.exit(500)
            end

            api_ctx.matched_route = route
        end

        local route_val = route.value
        if route_val.upstream and route_val.upstream.enable_websocket then
            enable_websocket = true
        end

        if route_val.upstream and route_val.upstream.pass_host then
            api_ctx.pass_host = route_val.upstream.pass_host
            api_ctx.upstream_host = route_val.upstream.upstream_host
        end

        api_ctx.matched_upstream = (route.dns_value and
                                    route.dns_value.upstream)
                                   or route_val.upstream
    end

    if enable_websocket then
        api_ctx.var.upstream_upgrade    = api_ctx.var.http_upgrade
        api_ctx.var.upstream_connection = api_ctx.var.http_connection
        core.log.info("enabled websocket for route: ", route.value.id)
    end

    if route.value.service_protocol == "grpc" then
        api_ctx.upstream_scheme = "grpc"
    end

    local code, err = set_upstream(route, api_ctx)
    if code then
        core.log.error("failed to set upstream: ", err)
        core.response.exit(code)
    end

    set_upstream_host(api_ctx)

    local up_scheme = api_ctx.upstream_scheme
    if up_scheme == "grpcs" or up_scheme == "grpc" then
        ngx_var.ctx_ref = ctxdump.stash_ngx_ctx()
        if ngx_version < 1017008 then
            return ngx.exec("@1_15_" .. up_scheme .. "_pass")
        end

        return ngx.exec("@grpc_pass")
    end

    if api_ctx.dubbo_proxy_enabled then
        ngx_var.ctx_ref = ctxdump.stash_ngx_ctx()
        return ngx.exec("@dubbo_pass")
    end
end


function _M.dubbo_access_phase()
    ngx.ctx = ctxdump.apply_ngx_ctx(ngx_var.ctx_ref)
end


function _M.grpc_access_phase()
    ngx.ctx = ctxdump.apply_ngx_ctx(ngx_var.ctx_ref)
end


local function common_phase(phase_name)
    local api_ctx = ngx.ctx.api_ctx
    if not api_ctx then
        return
    end

    plugin.run_global_rules(api_ctx, api_ctx.global_rules, phase_name)

    if api_ctx.script_obj then
        script.run(phase_name, api_ctx)
    else
        plugin.run_plugin(phase_name, nil, api_ctx)
    end

    return api_ctx
end


local function set_resp_upstream_status(up_status)
    core.response.set_header("X-APISIX-Upstream-Status", up_status)
    core.log.info("X-APISIX-Upstream-Status: ", up_status)
end


function _M.http_header_filter_phase()
    core.response.set_header("Server", ver_header)

    local up_status = get_var("upstream_status")
    core.log.debug("http_header_filter_phase upstream_status",
            core.json.delay_encode(up_status, true))
    if up_status and #up_status == 3
       and tonumber(up_status) >= 500
       and tonumber(up_status) <= 599
    then
        set_resp_upstream_status(up_status)
    elseif up_status and #up_status > 3 then
        -- the up_status can be "502, 502" or "502, 502 : "
        -- todo: 多个upstream，每个upstream的返回值?
        local last_status
        if str_byte(up_status, -1) == str_byte(" ") then
            last_status = str_sub(up_status, -6, -3)
        else
            last_status = str_sub(up_status, -3)
        end

        if tonumber(last_status) >= 500 and tonumber(last_status) <= 599 then
            set_resp_upstream_status(up_status)
        end
    end

    common_phase("header_filter")
end


function _M.http_body_filter_phase()
    common_phase("body_filter")
end

---@param api_ctx api_ctx
local function healthcheck_passive(api_ctx)
    local checker = api_ctx.up_checker
    if not checker then
        return
    end

    local up_conf = api_ctx.upstream_conf
    local passive = up_conf.checks.passive
    if not passive then
        return
    end

    core.log.info("enabled healthcheck passive")
    local host = up_conf.checks and up_conf.checks.active
                 and up_conf.checks.active.host
    local port = up_conf.checks and up_conf.checks.active
                 and up_conf.checks.active.port

    local resp_status = ngx.status
    local http_statuses = passive and passive.healthy and
                          passive.healthy.http_statuses
    core.log.info("passive.healthy.http_statuses: ",
                  core.json.delay_encode(http_statuses))
    if http_statuses then
        for i, status in ipairs(http_statuses) do
            if resp_status == status then
                checker:report_http_status(api_ctx.balancer_ip,
                                           port or api_ctx.balancer_port,
                                           host,
                                           resp_status)
            end
        end
    end

    http_statuses = passive and passive.unhealthy and
                    passive.unhealthy.http_statuses
    core.log.info("passive.unhealthy.http_statuses: ",
                  core.json.delay_encode(http_statuses))
    if not http_statuses then
        return
    end

    for i, status in ipairs(http_statuses) do
        for i, status in ipairs(http_statuses) do
            if resp_status == status then
                checker:report_http_status(api_ctx.balancer_ip,
                                           port or api_ctx.balancer_port,
                                           host,
                                           resp_status)
            end
        end
    end
end


function _M.http_log_phase()
    local api_ctx = common_phase("log")
    healthcheck_passive(api_ctx)

    if api_ctx.server_picker and api_ctx.server_picker.after_balance then
        api_ctx.server_picker.after_balance(api_ctx, false)
    end

    if api_ctx.uri_parse_param then
        core.tablepool.release("uri_parse_param", api_ctx.uri_parse_param)
    end

    core.ctx.release_vars(api_ctx)
    if api_ctx.plugins and api_ctx.plugins ~= core.empty_tab then
        core.tablepool.release("plugins", api_ctx.plugins)
    end

    if api_ctx.curr_req_matched then
        core.tablepool.release("matched_route_record", api_ctx.curr_req_matched)
    end

    core.tablepool.release("api_ctx", api_ctx)
end


function _M.http_balancer_phase()
    local api_ctx = ngx.ctx.api_ctx
    if not api_ctx then
        core.log.error("invalid api_ctx")
        return core.response.exit(500)
    end

    load_balancer(api_ctx.matched_route, api_ctx)
end


local function cors_admin()
    local_conf = core.config.local_conf()
    if local_conf.apisix and not local_conf.apisix.enable_admin_cors then
        return
    end

    local method = get_method()
    if method == "OPTIONS" then
        core.response.set_header("Access-Control-Allow-Origin", "*",
            "Access-Control-Allow-Methods",
            "POST, GET, PUT, OPTIONS, DELETE, PATCH",
            "Access-Control-Max-Age", "3600",
            "Access-Control-Allow-Headers", "*",
            "Access-Control-Allow-Credentials", "true",
            "Content-Length", "0",
            "Content-Type", "text/plain")
        ngx_exit(200)
    end

    core.response.set_header("Access-Control-Allow-Origin", "*",
                            "Access-Control-Allow-Credentials", "true",
                            "Access-Control-Expose-Headers", "*",
                            "Access-Control-Max-Age", "3600")
end

local function add_content_type()
    core.response.set_header("Content-Type", "application/json")
end

do
    local router

function _M.http_admin()
    if not router then
        router = admin_init.get()
    end

    -- add cors rsp header
    cors_admin()

    -- add content type to rsp header
    add_content_type()

    -- core.log.info("uri: ", get_var("uri"), " method: ", get_method())
    local ok = router:dispatch(get_var("uri"), {method = get_method()})
    if not ok then
        ngx_exit(404)
    end
end

end -- do


function _M.http_control()
    local ok = control_api_router.match(get_var("uri"))
    if not ok then
        ngx_exit(404)
    end
end


function _M.stream_init()
    core.log.info("enter stream_init")

    if core.config.init then
        local ok, err = core.config.init()
        if not ok then
            core.log.error("failed to load the configuration: ", err)
        end
    end
end


function _M.stream_init_worker()
    core.log.info("enter stream_init_worker")
    local seed, err = core.utils.get_seed_from_urandom()
    if not seed then
        core.log.warn('failed to get seed from urandom: ', err)
        seed = ngx_now() * 1000 + ngx.worker.pid()
    end
    math.randomseed(seed)
    -- for testing only
    core.log.info("random stream test in [1, 10000]: ", math.random(1, 10000))

    router.stream_init_worker()
    plugin.init_worker()

    if core.config == require("apisix.core.config_yaml") then
        core.config.init_worker()
    end

    load_balancer = require("apisix.balancer").run

    local_conf = core.config.local_conf()
end


function _M.stream_preread_phase()
    core.log.info("enter stream_preread_phase")

    local ngx_ctx = ngx.ctx
    local api_ctx = ngx_ctx.api_ctx

    if not api_ctx then
        api_ctx = core.tablepool.fetch("api_ctx", 0, 32)
        ngx_ctx.api_ctx = api_ctx
    end

    core.ctx.set_vars_meta(api_ctx)

    router.router_stream.match(api_ctx)

    core.log.info("matched route: ",
                  core.json.delay_encode(api_ctx.matched_route, true))

    local matched_route = api_ctx.matched_route
    if not matched_route then
        return ngx_exit(1)
    end

    local plugins = core.tablepool.fetch("plugins", 32, 0)
    api_ctx.plugins = plugin.stream_filter(matched_route, plugins)
    -- core.log.info("valid plugins: ", core.json.delay_encode(plugins, true))

    api_ctx.matched_upstream = matched_route.value.upstream
    api_ctx.conf_type = "stream/route"
    api_ctx.conf_version = matched_route.modifiedIndex
    api_ctx.conf_id = matched_route.value.id

    plugin.run_plugin("preread", plugins, api_ctx)

    local code, err = set_upstream(matched_route, api_ctx)
    if code then
        core.log.error("failed to set upstream: ", err)
        return ngx_exit(1)
    end
end


function _M.stream_balancer_phase()
    core.log.info("enter stream_balancer_phase")
    local api_ctx = ngx.ctx.api_ctx
    if not api_ctx then
        core.log.error("invalid api_ctx")
        return ngx_exit(1)
    end

    load_balancer(api_ctx.matched_route, api_ctx)
end


function _M.stream_log_phase()
    core.log.info("enter stream_log_phase")
    -- core.ctx.release_vars(api_ctx)
    plugin.run_plugin("log")
end


return _M
