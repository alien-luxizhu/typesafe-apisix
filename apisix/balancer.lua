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
local require           = require
local balancer          = require("ngx.balancer")
local core              = require("apisix.core")
local priority_balancer = require("apisix.balancer.priority")
local ipairs            = ipairs
local set_more_tries   = balancer.set_more_tries
local get_last_failure = balancer.get_last_failure
local set_timeouts     = balancer.set_timeouts


local module_name = "balancer"
local pickers = {}

local lrucache_server_picker = core.lrucache.new({
    ttl = 300, count = 256
})
local lrucache_addr = core.lrucache.new({
    ttl = 300, count = 1024 * 4
})


local _M = {
    version = 0.2,
    name = module_name,
}


local function transform_node(new_nodes, node)
    if not new_nodes._priority_index then
        new_nodes._priority_index = {}
    end

    if not new_nodes[node.priority] then
        new_nodes[node.priority] = {}
        core.table.insert(new_nodes._priority_index, node.priority)
    end

    new_nodes[node.priority][node.host .. ":" .. node.port] = node.weight
    return new_nodes
end

---@param upstream upstream_t
local function fetch_health_nodes(upstream, checker)
    local nodes = upstream.nodes
    if not checker then
        local new_nodes = core.table.new(0, #nodes)
        for _, node in ipairs(nodes) do
            new_nodes = transform_node(new_nodes, node)
        end
        return new_nodes
    end

    local host = upstream.checks and upstream.checks.active and upstream.checks.active.host
    local port = upstream.checks and upstream.checks.active and upstream.checks.active.port
    local up_nodes = core.table.new(0, #nodes)
    for _, node in ipairs(nodes) do
        local ok, err = checker:get_target_status(node.host, port or node.port, host)
        if ok then
            up_nodes = transform_node(up_nodes, node)
        elseif err then
            core.log.error("failed to get health check target status, addr: ",
                node.host, ":", port or node.port, ", host: ", host, ", err: ", err)
        end
    end

    if core.table.nkeys(up_nodes) == 0 then
        core.log.warn("all upstream nodes is unhealthy, use default")
        for _, node in ipairs(nodes) do
            up_nodes = transform_node(up_nodes, node)
        end
    end

    return up_nodes
end

---@param upstream upstream_t
local function create_server_picker(upstream, checker)
    local picker = pickers[upstream.type]
    if not picker then
        pickers[upstream.type] = require("apisix.balancer." .. upstream.type)
        picker = pickers[upstream.type]
    end

    if picker then
        local up_nodes = fetch_health_nodes(upstream, checker)

        if #up_nodes._priority_index > 1 then
            core.log.info("upstream nodes: ", core.json.delay_encode(up_nodes))
            return priority_balancer.new(up_nodes, upstream, picker)
        end

        core.log.info("upstream nodes: ",
                      core.json.delay_encode(up_nodes[up_nodes._priority_index[1]]))
        return picker.new(up_nodes[up_nodes._priority_index[1]], upstream)
    end

    return nil, "invalid balancer type: " .. upstream.type, 0
end


local function parse_addr(addr)
    local host, port, err = core.utils.parse_addr(addr)
    return {host = host, port = port}, err
end

---@param route etcd_route_node_t
---@param ctx api_ctx
local function pick_server(route, ctx)
    core.log.info("route: ", core.json.delay_encode(route, true))
    core.log.info("ctx: ", core.json.delay_encode(ctx, true))
    local up_conf = ctx.upstream_conf

    if up_conf.timeout then
        local timeout = up_conf.timeout
        local ok, err = set_timeouts(timeout.connect, timeout.send,
                                     timeout.read)
        if not ok then
            core.log.error("could not set upstream timeouts: ", err)
        end
    end

    local nodes_count = #up_conf.nodes
    if nodes_count == 1 then
        local node = up_conf.nodes[1]
        ctx.balancer_ip = node.host
        ctx.balancer_port = node.port
        return node
    end

    local version = ctx.upstream_version
    local key = ctx.upstream_key
    local checker = ctx.up_checker

    ctx.balancer_try_count = (ctx.balancer_try_count or 0) + 1
    -- upstream的一个节点失败后，会去请求下一个节点，balancer_try_count会增加
    if ctx.balancer_try_count > 1 then
        if ctx.server_picker and ctx.server_picker.after_balance then
            ctx.server_picker.after_balance(ctx, true)
        end

        if checker then
            local state, code = get_last_failure()
            local host = up_conf.checks and up_conf.checks.active and up_conf.checks.active.host
            local port = up_conf.checks and up_conf.checks.active and up_conf.checks.active.port
            if state == "failed" then
                if code == 504 then
                    checker:report_timeout(ctx.balancer_ip, port or ctx.balancer_port, host)
                else
                    checker:report_tcp_failure(ctx.balancer_ip, port or ctx.balancer_port, host)
                end
            else
                checker:report_http_status(ctx.balancer_ip, port or ctx.balancer_port, host, code)
            end
        end
    end
    core.log.debug("up_conf.retries: ",
            core.json.delay_encode(up_conf.retries, true),
            "; up_conf.nodes num: ", core.json.delay_encode(#up_conf.nodes, true))
    if ctx.balancer_try_count == 1 then
        local retries = up_conf.retries
        if not retries or retries < 0 then
            retries = #up_conf.nodes - 1
        end

        if retries > 0 then
            set_more_tries(retries)
        end
    end

    if checker then
        version = version .. "#" .. checker.status_ver
    end

    -- the same picker will be used in the whole request, especially during the retry
    local server_picker = ctx.server_picker
    if not server_picker then
        server_picker = lrucache_server_picker(key, version,
                                               create_server_picker, up_conf, checker)
    end
    if not server_picker then
        return nil, "failed to fetch server picker"
    end

    -- server是一个 balancer_tried_servers的下标
    local server, err = server_picker.get(ctx)
    if not server then
        err = err or "no valid upstream node"
        return nil, "failed to find valid upstream server, " .. err
    end
    ctx.balancer_server = server

    local res, err = lrucache_addr(server, nil, parse_addr, server)
    ctx.balancer_ip = res.host
    ctx.balancer_port = res.port
    -- core.log.info("cached balancer peer host: ", host, ":", port)
    if err then
        core.log.error("failed to parse server addr: ", server, " err: ", err)
        return core.response.exit(502)
    end
    ctx.server_picker = server_picker
    return res
end


-- for test
_M.pick_server = pick_server

---@param route etcd_route_node_t
---@param ctx api_ctx
function _M.run(route, ctx)
    -- 一个upstream有多个节点，某个节点失败后，会去请求下一个节点，直到把每个节点都请求一遍
    core.log.debug("balancer run: route", core.json.delay_encode(route, true))
    --core.log.debug("balancer run: ctx", core.json.delay_encode(ctx, true))
    --[[

    {
        "key": "\/apisix\/routes\/348388866928938607",
        "value": {
            "create_time": 1617185546,
            "desc": "hello11111111222",
            "hosts": ["*.sjz     qtest1.com"],
            "name": "beijing",
            "update_time": 1617357655,
            "status": 1,
            "uris": ["\/api\/test1"],
            "vars": [
                ["http_agent", "==", "ios-5.7.0"]
            ],
            "id": "348388866928938607",
            "upstream_id": "348387005614263919",
            "priority": 0,
            "meth     ods": ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
            "plugins": {
                "limit-count": {
                    "rejected_code": 503,
                    "count": 10,
                    "redis_database": 0,
                    "time_window": 10,
                    "policy": "local",
                    "key": "remote_addr",
                    "redis_timeout": 1000,
                    "redis_port": 6379
                }
            }
        },
        "has_domain": false,
        "clean_handlers": {},
        "createdIndex": 641,
        "update_count": 0,
        "orig_mo     difiedIndex": 2163,
        "modifiedIndex": 2163
    }
    --]]

    local server, err = pick_server(route, ctx)
    if not server then
        core.log.error("failed to pick server: ", err)
        return core.response.exit(502)
    end

    core.log.info("proxy request to ", server.host, ":", server.port)
    local ok, err = balancer.set_current_peer(server.host, server.port)
    if not ok then
        core.log.error("failed to set server peer [", server.host, ":",
                       server.port, "] err: ", err)
        return core.response.exit(502)
    end

    ctx.proxy_passed = true
end


function _M.init_worker()
end

return _M
