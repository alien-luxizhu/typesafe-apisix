---
--- Generated by EmmyLua(https://github.com/EmmyLua)
--- Created by luxizhu.
--- DateTime: 2021/3/11 9:55
--- cli/etcd依赖太重, 为此重新实现
--- 部署好etcd配置好config.yaml，在web-switch目录下执行
---   ./bin/openresty/bin/resty -I ./deps/share/lua/5.1 apisix/own/init-etcd.lua
---


local require = require
local ngx = ngx
local http = require "resty.http"
local cjson = require("cjson")
local base64_encode = ngx.encode_base64
local yaml = require("tinyyaml")
local constants = require("apisix.constants")

-- 加载配置文件conf/config.yaml
local file_path = "./conf/config.yaml"
local file, err = io.open(file_path, "rb")
if not file then
    print("failed to open file: ", file_path, ", error info:", err)
    return
end

local data, err = file:read("*all")
if err ~= nil then
    file:close()
    print("failed to read file: ", file_path, ", error info:", err)
    return
end
file:close()

local yaml_conf = yaml.parse(data)
if not yaml_conf then
    print("parse conf file error, ", err)
    return
end

local etcd_conf = yaml_conf.etcd
local prefix = etcd_conf.prefix or ""

local dirs = {}
for name in pairs(constants.HTTP_ETCD_DIRECTORY) do
    dirs[name] = true
end
for name in pairs(constants.STREAM_ETCD_DIRECTORY) do
    dirs[name] = true
end

-- 向每个etcd.host发送http请求
for _, host in ipairs(etcd_conf.host) do
    for dir_name in pairs(dirs) do
        -- 创建目录"/apisix/routes/"
        local key = prefix .. dir_name .. "/"
        local put_url = host .. "/v3/kv/put"
        local post_json = {
            value = base64_encode("init_dir"),
            key = base64_encode(key)
        }
        local params = {
            method = "POST",
            body = cjson.encode(post_json),
        }
        local httpc = http.new()
        local res, err = httpc:request_uri(put_url, params)
        print(dir_name, "===>", put_url, ",", params.body)
        if err then
            print(err)
        else
            print("<===", res.status, ",", res.body)
        end
    end
end