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

local table        = require("apisix.core.table")
local config_local = require("apisix.core.config_local")
local log          = require("apisix.core.log")
local json         = require("apisix.core.json")
local etcd_apisix  = require("apisix.core.etcd")
local core_str     = require("apisix.core.string")
local etcd         = require("resty.etcd")
local new_tab      = require("table.new")
local clone_tab    = require("table.clone")
local check_schema = require("apisix.core.schema").check
local exiting      = ngx.worker.exiting
local insert_tab   = table.insert
local type         = type
local ipairs       = ipairs
local setmetatable = setmetatable
local ngx_sleep    = require("apisix.core.utils").sleep
local ngx_timer_at = ngx.timer.at
local ngx_time     = ngx.time
local sub_str      = string.sub
local tostring     = tostring
local tonumber     = tonumber
local xpcall       = xpcall
local debug        = debug
local error        = error
local rand         = math.random
local constants    = require("apisix.constants")


local is_http = ngx.config.subsystem == "http"
---@type table<string, config_etcd>
local created_obj  = {}
local loaded_configuration = {}

---
---@field etcd_cli resty_etcd_v3_client
---@field values etcd_v2_node[]
---@field conf_version number
---@field need_reload number
---@field filter fun(value):void
---@field checker fun(value):boolean
---@class config_etcd
local _M = {
    version = 0.3,
    local_conf = config_local.local_conf,
    clear_local_cache = config_local.clear_cache,
}


local mt = {
    __index = _M,
    __tostring = function(self)
        return " etcd key: " .. self.key
    end
}


local function getkey(etcd_cli, key)
    if not etcd_cli then
        return nil, "not inited"
    end

    local res, err = etcd_cli:readdir(key)
    if not res then
        -- log.error("failed to get key from etcd: ", err)
        return nil, err
    end

    if type(res.body) ~= "table" then
        return nil, "failed to get key from etcd"
    end

    res, err = etcd_apisix.get_format(res, key, true)
    if not res then
        return nil, err
    end

    return res
end

---@param etcd_cli resty_etcd_v3_client
---@return etcd_v2_dir_res
local function readdir(etcd_cli, key, formatter)
    if not etcd_cli then
        return nil, "not inited"
    end

    local res, err = etcd_cli:readdir(key)
    if not res then
        -- log.error("failed to get key from etcd: ", err)
        return nil, err
    end

    log.debug("readdir key ",key, "res is ", json.delay_encode(res.body))
    --[[
        readdir(): readdir key /apisix/plugin_configs
        res is {
            "header":{"cluster_id":"14841639068965178418",
                "revision":"1644","member_id":"10276657743932975437",
                "raft_term":"2"}}
    --]]

    --[[
        readdir key / apisix / routes
 res is {
	"header": {
		"cluster_id": "14841639068965178418",
		"revision": "1644",
		"member_id": "10276657743932975437    ",
		"raft_term": "2"
	},
	"kvs": [{
		"create_revision": "2",
		"mod_revision": "1642",
		"key": "\/apisix\/routes\/",
		"version": "20"
	}, {
		"create_revision": "641",
		"mod_revision": "1590",
		"value": {
			"create_time": 1617185546,
			"upstream_id": "348387005614263919",
			"name": "beijing",
			"update_time": 1617241906,
			"vars": [
				["http_agent", "==", "ios-5.7.0"]
			],
			"uris    ": ["\/api\/test1"],
			"plugins": {
				"limit-count": {
					"rejected_code": 503,
					"time_window": 10,
					"policy": "local",
					"key": "    remote_addr",
					"count": 10
				}
			},
			"desc": "hello",
			"methods": ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
			"id": "348388866928938607",
			"hosts": ["*.sjzqtest1.com"]
		},
		"key": "\/apisix\/routes\/348388866928938607",
		"versi    on": "2"
	}],
	"count": "2"
}


{-- readdir key /apisix/plugin_configs
	"count": "1",
	"header": {
		"raft_term": "2",
		"cluster_id": "14841639068965178418",
		"revision": "2020",
		"member_id": "10276657743932975437"
	},
	"kvs": [{
		"key": "\/apisix\/plugin_configs\/",
		"create_revision": "2019",
		"mod_revision": "2019",
		"version": "1"
	}]
}


{-- readdir key /apisix/upstreams
	"count": "3",
	"header": {
		"raft_term": "2",
		"cluster_id": "14841639068965178418",
		"revision": "2019",
		"member_id": "10276657743932975437"
	},
	"kvs": [{
		"key": "\/apisix\/upstreams\/",
		"create_revision": "3",
		"mod_revision": "2008",
		"version": "33"
	}, {
		"key": "\/apisix\/upstreams\/348343457934216815",
		"value": {
			"checks": {
				"active": {
					"http_path": "\/api\/news20\/xxx",
					"unhealthy": {
						"interval": 1,
						"http_failures": 1
					},
					"timeout": 1,
					"healthy": {
						"interval": 1,
						"successes": 3
					},
					"host": "www.aaa.com"
				}
			},
			"name": "news-service",
			"type": "roundrobin",
			"timeout": {
				"connect": 6000,
				"read": 6000,
				"send": 6000
			},
			"update_time": 1617176254,
			"id": "348343457934216815",
			"nodes": [{
				"host": "10.101.222.24",
				"weight": 1,
				"port": 9800
			}],
			"create_time": 1617158480
		},
		"create_revision": "67",
		"mod_revision": "338",
		"version": "2"
	}, {
		"key": "\/apisix\/upstreams\/348387005614263919",
		"value": {
			"checks": {
				"active": {
					"unhealthy": {
						"interval": 3,
						"http_failures": 3
					},
					"http_path": "\/api\/test1",
					"healthy": {
						"interval": 3,
						"successes": 3
					},
					"host": "abc.com"
				}
			},
			"name": "test",
			"type": "roundrobin",
			"timeout": {
				"connect": 6000,
				"read": 6000,
				"send": 6000
			},
			"update_time": 1617184437,
			"id": "348387005614263919",
			"nodes": [{
				"host": "10.101.222.24",
				"weight": 1,
				"port": 9800
			}, {
				"host": "10.101.222.24",
				"weight": 1,
				"port": 8001
			}],
			"create_time": 1617184437
		},
		"create_revision": "610",
		"mod_revision": "610",
		"version": "1"
	}]
}





    --]]

    if type(res.body) ~= "table" then
        return nil, "failed to read etcd dir"
    end

    res, err = etcd_apisix.get_format(res, key .. '/', true, formatter)
    if not res then
        return nil, err
    end

    return res
end

---@param etcd_cli resty_etcd_v3_client
---@return etcd_v2_dir_res
local function waitdir(etcd_cli, key, modified_index, timeout)
    if not etcd_cli then
        return nil, nil, "not inited"
    end

    local opts = {}
    opts.start_revision = modified_index
    opts.timeout = timeout
    opts.need_cancel = true
    local res_func, func_err, http_cli = etcd_cli:watchdir(key, opts)
    if not res_func then
        return nil, func_err
    end

    -- in etcd v3, the 1st res of watch is watch info, useless to us.
    -- try twice to skip create info
    local res, err = res_func()
    if not res or not res.result or not res.result.events then
        res, err = res_func()
    end

    if http_cli then
        local res_cancel, err_cancel = etcd_cli:watchcancel(http_cli)
        if res_cancel == 1 then
            log.info("cancel watch connection success")
        else
            log.error("cancel watch failed: ", err_cancel)
        end
    end

    if not res then
        -- log.error("failed to get key from etcd: ", err)
        return nil, err
    end

    if type(res.result) ~= "table" then
        return nil, "failed to wait etcd dir"
    end
    log.info("watch_format: res :", json.delay_encode(res, true))
    --[[
    {
        "result": {
            "header": {
                "cluster_id": "14841639068965178418",
                "revision": "1911",
                "member_id": "10276657743932975437",
                "raft_term": "2"
            },
            "events": [{
                "kv": {
                    "key": "\/apisix\/routes\/348388866928938607",
                    "create_revision": "641",
                    "mod_revision": "1911",
                    "value": {
                        "name": "beijing",
                        "methods": ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS      ", "PATCH"],
                        "hosts": ["*.sjzqtest1.com"],
                        "create_time": 1617185546,
                        "desc": "hello11111",
                        "upstream_id": "348387005614263919",
                        "update_time": 1617260284,
                        "plugins": {
                            "limit-count": {
                                "count": 10,
                                "policy": "local",
                                "key": "remote_addr",
                                "time_window": 10,
                                "rejected_code": 503
                            }
                        },
                        "vars": [
                            ["http_agent", "==", "ios-5.7.0"]
                        ],
                        "uris": ["\/api\/test1"],
                        "id": "348388866928938607"
                    },
                    "version": "4"
                }
            }]
        }
    }


    {
        "result": {
            "header": {
                "member_id": "10276657743932975437",
                "cluster_id": "14841639068965178418",
                "revision": "1984",
                "raft_term": "2"
            },
            "events": [{
                "type": "DELETE",
                "kv": {
                    "mod_revision": "1984",
                    "key": "\/apisix\/routes\/348520304554806895"
                }
            }]
        }
    }


    {-- upstream
	"reason": "OK",
	"read_trailers": "function: 0x7fc026fefd90",
	"headers": {
		"Access-Control-Allow-Headers": "accept, content-type, authorization",
		"Access-Control-Allow-Origin": "*",
		"Content-Length": "1599",
		"Access-Control-Allow-Methods": "POST, GET, OPTIONS, PUT, DELETE",
		"Content-Type": "application\/json",
		"X-Etcd-Index": "2019",
		"Date": "Fri, 02 Apr 2021 02:49:45 GMT",
		"Grpc-Metadata-Content-Type": "application\/grpc"
	},
	"read_body": "function: 0x7fc026fe9af8",
	"has_body": true,
	"body_reader": "function: 0x7fc0390a1060",
	"status": 200,
	"body": {
		"action": "get",
		"count": "3",
		"header": {
			"raft_term": "2",
			"cluster_id": "14841639068965178418",
			"member_id": "10276657743932975437",
			"revision": "2019"
		},
		"node": {
			"key": "\/apisix\/upstreams",
			"dir": true,
			"nodes": [{
				"key": "\/apisix\/upstreams\/348343457934216815",
				"value": {
					"checks": {
						"active": {
							"http_path": "\/api\/news20\/xxx",
							"unhealthy": {
								"interval": 1,
								"http_failures": 1
							},
							"timeout": 1,
							"healthy": {
								"interval": 1,
								"successes": 3
							},
							"host": "www.aaa.com"
						}
					},
					"name": "news-service",
					"type": "roundrobin",
					"nodes": [{
						"port": 9800,
						"weight": 1,
						"host": "10.101.222.24"
					}],
					"update_time": 1617176254,
					"timeout": {
						"connect": 6000,
						"read": 6000,
						"send": 6000
					},
					"id": "348343457934216815",
					"create_time": 1617158480
				},
				"createdIndex": 67,
				"modifiedIndex": 338
			}, {
				"key": "\/apisix\/upstreams\/348387005614263919",
				"value": {
					"checks": {
						"active": {
							"host": "abc.com",
							"healthy": {
								"interval": 3,
								"successes": 3
							},
							"http_path": "\/api\/test1",
							"unhealthy": {
								"interval": 3,
								"http_failures": 3
							}
						}
					},
					"name": "test",
					"type": "roundrobin",
					"nodes": [{
						"port": 9800,
						"weight": 1,
						"host": "10.101.222.24"
					}, {
						"port": 8001,
						"weight": 1,
						"host": "10.101.222.24"
					}],
					"update_time": 1617184437,
					"timeout": {
						"connect": 6000,
						"read": 6000,
						"send": 6000
					},
					"id": "348387005614263919",
					"create_time": 1617184437
				},
				"createdIndex": 610,
				"modifiedIndex": 610
			}],
			"modifiedIndex": 2008,
			"createdIndex": 3
		}
	}
}

    --]]

    return etcd_apisix.watch_format(res)
end


local function short_key(self, str)
    return sub_str(str, #self.key + 2)
end


local function load_full_data(self, dir_res, headers)
    local err
    local changed = false

    if self.single_item then
        self.values = new_tab(1, 0)
        self.values_hash = new_tab(0, 1)

        local item = dir_res
        local data_valid = item.value ~= nil

        if data_valid and self.item_schema then
            data_valid, err = check_schema(self.item_schema, item.value)
            if not data_valid then
                log.error("failed to check item data of [", self.key,
                          "] err:", err, " ,val: ", json.encode(item.value))
            end
        end

        if data_valid and self.checker then
            data_valid, err = self.checker(item.value)
            if not data_valid then
                log.error("failed to check item data of [", self.key,
                          "] err:", err, " ,val: ", json.delay_encode(item.value))
            end
        end

        if data_valid then
            changed = true
            insert_tab(self.values, item)
            self.values_hash[self.key] = #self.values

            item.clean_handlers = {}

            if self.filter then
                self.filter(item)
            end
        end

        self:upgrade_version(item.modifiedIndex)

    else
        if not dir_res.nodes then
            dir_res.nodes = {}
        end

        self.values = new_tab(#dir_res.nodes, 0)
        self.values_hash = new_tab(0, #dir_res.nodes)

        for _, item in ipairs(dir_res.nodes) do
            local key = short_key(self, item.key)
            local data_valid = true
            if type(item.value) ~= "table" then
                data_valid = false
                log.error("invalid item data of [", self.key .. "/" .. key,
                          "], val: ", item.value,
                          ", it should be an object")
            end

            if data_valid and self.item_schema then
                data_valid, err = check_schema(self.item_schema, item.value)
                if not data_valid then
                    log.error("failed to check item data of [", self.key,
                              "] err:", err, " ,val: ", json.encode(item.value))
                end
            end

            if data_valid and self.checker then
                data_valid, err = self.checker(item.value)
                if not data_valid then
                    log.error("failed to check item data of [", self.key,
                              "] err:", err, " ,val: ", json.delay_encode(item.value))
                end
            end

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

            self:upgrade_version(item.modifiedIndex)
        end
    end

    if headers then
        self:upgrade_version(headers["X-Etcd-Index"])
    end

    if changed then
        self.conf_version = self.conf_version + 1
    end

    self.need_reload = false
end


function _M.upgrade_version(self, new_ver)
    new_ver = tonumber(new_ver)
    if not new_ver then
        return
    end

    local pre_index = self.prev_index

    if new_ver <= pre_index then
        return
    end

    self.prev_index = new_ver
    return
end

---@param self config_etcd
local function sync_data(self)
    if not self.key then
        return nil, "missing 'key' arguments"
    end

    if self.need_reload then
        local res, err = readdir(self.etcd_cli, self.key)
        log.debug("sync_data res: ",
                  json.delay_encode(res,true))
        --[[

    {--??????
	"has_body": true,
	"body_reader": "function: 0x7f7598f8a5f8",
	"read_body": "function: 0x7f759df3c858",
	"headers": {
		"Date": "Thu, 01 Apr 2021 02:40:11 GMT",
		"Access-Control-Allow-Headers": "accept, content-type, authorization",
		"X-Etcd-Index": "1644",
		"Access-Control-Allow-Origin": "*",
		"Grpc-Metadata-Content-Type": "application\/grpc",
		"Content-Type": "application\/json",
		"Access-Control-Allow-Methods": "POST, GET, OPTIONS, PUT, DELETE",
		"Content-Length": "928"
	},
	"reason": "OK",
	"body": {
		"count": "2",
		"header": {
			"cluster_id": "14841639068965178418",
			"member_id": "10276657743932975437",
			"revision": "1644",
			"raft_term": "2"
		},
		"action": "get",
		"node": {
			"modifiedIndex": 1642,
			"nodes": [{
				"key": "\/apisix\/routes\/348388866928938607",
				"modifiedIndex": 1590,
				"value": {
					"create_time": 1617185546,
					"upstream_id": "348387005614263919",
					"name": "beijing",
					"update_time": 1617241906,
					"vars": [
						["http_agent", "==", "ios-5.7.0"]
					],
					"uris": ["\/api\/test1"],
					"desc": "hello",
					"plugins": {
						"limit-count": {
							"rejected_code": 503,
							"time_window": 10,
							"policy": "local",
							"key": "remote_addr",
							"count": 10
						}
					},
					"methods": ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
					"id": "348388866928938607",
					"hosts": ["*.sjzqtest1.com"]
				},
				"createdIndex": 641
			}],
			"key": "\/apisix\/routes",
			"dir": true,
			"createdIndex": 2
		}
	},
	"read_trailers": "function: 0x7f759df3c978",
	"status": 200
}



{ -- plugin_configs???init-etcd?????????plugin_configs??????
	"headers": {
		"Access-Control-Allow-Origin": "*",
		"X-Etcd-Index": "2007",
		"Access-Control-Allow-Methods": "POST, GET     , OPTIONS, PUT, DELETE",
		"Content-Type": "application\/json",
		"Grpc-Metadata-Content-Type": "application\/grpc",
		"Date": "Fri, 02 Apr 2021 02:43:08 GMT",
		"Content-Length": "117",
		"Access-Control-Allow-Headers": "accept,      content-type, authorization"
	},
	"status": 404,
	"read_trailers": "function: 0x7f759df4bb18",
	"reason": "Not found     ",
	"has_body": true,
	"body_reader": "function: 0x7f758eae0bf0",
	"body": {
		"message": "Key not found",
		"header": {
			"raft_term": "2",
			"cluster_id": "14841639068965178418",
			"revision": "2007",
			"member_id": "10276657743932975437"
		}
	},
	"read_body": "function: 0x7f759df45520"
}


{ -- plugin_configs???init-etcd??????plugin_configs????????????stop.sh???start.sh????????????
	"reason": "OK",
	"read_trailers": "function: 0x7fc026fefd90",
	"headers": {
		"Access-Control-Allow-Headers": "accept, content-type, authorization",
		"Access-Control-Allow-Origin": "*",
		"Content-Length": "264",
		"Access-Control-Allow-Methods": "POST, GET, OPTIONS, PUT, DELETE",
		"Content-Type": "application\/json",
		"X-Etcd-Index": "2020",
		"Date": "Fri, 02 Apr 2021 02:49:45 GMT",
		"Grpc-Metadata-Content-Type": "application\/grpc"
	},
	"read_body": "function: 0x7fc026fe9af8",
	"has_body": true,
	"body_reader": "function: 0x7fc01796cd18",
	"status": 200,
	"body": {
		"action": "get",
		"count": "1",
		"header": {
			"raft_term": "2",
			"cluster_id": "14841639068965178418",
			"member_id": "10276657743932975437",
			"revision": "2020"
		},
		"node": {
			"key": "\/apisix\/plugin_configs",
			"dir": true,
			"nodes": {},
			"modifiedIndex": 2019,
			"createdIndex": 2019
		}
	}
}

{-- upstream:
	"count": "3",
	"header": {
		"raft_term": "2",
		"cluster_id": "14841639068965178418",
		"revision": "2019",
		"      member_id": "10276657743932975437"
	},
	"kvs": [{
		"key": "\/apisix\/upstreams\/",
		"create_revision": "3",
		"mod_revi      sion": "2008",
		"version": "33"
	}, {
		"key": "\/apisix\/upstreams\/348343457934216815",
		"value": {
			"checks": {
				"active      ": {
					"http_path": "\/api\/news20\/xxx",
					"unhealthy": {
						"interval": 1,
						"http_failures": 1
					},
					"timeout": 1,
					"healthy": {
						"interval": 1,
						"successes": 3
					},
					"host": "www.aaa.com"
				}
			},
			"name": "news-service",
			"type": "roundrobin",
			"timeout": {
				"connect": 6000,
				"read": 6000,
				"send": 6000
			},
			"update_time": 1617176254,
			"id": "348343457934216815",
			"nodes": [{
				"ho      st": "10.101.222.24",
				"weight": 1,
				"port": 9800
			}],
			"create_time": 1617158480
		},
		"create_revision": "67",
		"mod_revis      ion": "338",
		"version": "2"
	}, {
		"key": "\/apisix\/upstreams\/348387005614263919",
		"value": {
			"checks": {
				"active": {
					"unhealthy": {
						"interval": 3,
						"http_failures": 3
					},
					"http_path": "\/api\/test1",
					"healthy": {
						"interval": 3,
						"successes": 3
					},
					"host": "abc.com"
				}
			},
			"name": "test",
			"type": "roundrobin",
			"timeout": {
				"connect": 6000,
				"read": 6000,
				"send": 6000
			},
			"update_time": 1617184437,
			"id": "348387005614263919",
			"nodes": [{
				"host": "10.101.222.24",
				"weight": 1,
				"port": 9800
			}, {
				"host": "10.101.222.24",
				"weight": 1,
				"port": 8001
			}],
			"create_time": 1617184437
		},
		"create_revision": "610",
		"mod_revision": "610",
		"version": "1"
	}]
}


        --]]


        if not res then
            return false, err
        end

        local dir_res, headers = res.body.node or {}, res.headers
        log.debug("readdir key: ", self.key, " res: ",
                  json.delay_encode(dir_res))
        if not dir_res then
            return false, err
        end
        -- nginx??????????????????self.values???nil
        if self.values then
            for i, val in ipairs(self.values) do
                if val and val.clean_handlers then
                    for _, clean_handler in ipairs(val.clean_handlers) do
                        clean_handler(val)
                    end
                    val.clean_handlers = nil
                end
            end

            self.values = nil
            self.values_hash = nil
        end

        load_full_data(self, dir_res, headers)

        return true
    end

    local dir_res, err = waitdir(self.etcd_cli, self.key, self.prev_index + 1, self.timeout)
    log.info("waitdir key: ", self.key, " prev_index: ", self.prev_index + 1)
    log.info("config_etcd waitdir dir_res: ", json.delay_encode(dir_res, true))
    --[[
    {   ????????????
        "body": {
            "node": [{
                "createdIndex": 641,
                "key": "\/apisix\/routes\/348388866928938607",
                "value": {
                    "uris": ["\/api\/test1"],
                    "methods": ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
                    "hosts": ["*.sjzqtes      t1.com"],
                    "update_time": 1617261882,
                    "desc": "hello11111111222",
                    "id": "348388866928938607",
                    "name": "beijing",
                    "plugins": {
                        "limit-count": {
                            "time_window": 10,
                            "policy": "local",
                            "rejected_code": 503,
                            "key": "remote_addr",
                            "count": 10
                        }
                    },
                    "vars": [
                        ["http_agent", "==", "ios-5.7.0"]
                    ],
                    "upstream_id": "348387005614263919",
                    "create_time": 161718 5546
                },
                "modifiedIndex": 1944
            }]
        },
        "headers": {
            "X-Etcd-Index": "1944"
        }
    }

    {   ????????????
        "headers": {
            "X-Etcd-Index": "1984"
        },
        "body": {
            "action": "delete",
            "node": [{
                "key": "\/apisix\/routes\/348520304554806895",
                "modifiedIndex": 1984
            }]
        }
    }



    --]]

    if not dir_res then
        if err == "compacted" then
            self.need_reload = true
            log.warn("waitdir [", self.key, "] err: ", err,
                     ", will read the configuration again via readdir")
            return false
        end

        return false, err
    end

    local res = dir_res.body.node
    local err_msg = dir_res.body.message
    if err_msg then
        return false, err
    end

    if not res then
        return false, err
    end

    local res_copy = res
    -- waitdir will return [res] even for self.single_item = true
    for _, res in ipairs(res_copy) do
        local key
        if self.single_item then
            key = self.key
        else
            key = short_key(self, res.key)
        end

        if res.value and not self.single_item and type(res.value) ~= "table" then
            self:upgrade_version(res.modifiedIndex)
            return false, "invalid item data of [" .. self.key .. "/" .. key
                            .. "], val: " .. res.value
                            .. ", it should be an object"
        end

        if res.value and self.item_schema then
            local ok, err = check_schema(self.item_schema, res.value)
            if not ok then
                self:upgrade_version(res.modifiedIndex)

                return false, "failed to check item data of ["
                                .. self.key .. "] err:" .. err
            end

            if self.checker then
                local ok, err = self.checker(res.value)
                if not ok then
                    self:upgrade_version(res.modifiedIndex)

                    return false, "failed to check item data of ["
                                    .. self.key .. "] err:" .. err
                end
            end
        end

        self:upgrade_version(res.modifiedIndex)

        if res.dir then
            if res.value then
                return false, "todo: support for parsing `dir` response "
                                .. "structures. " .. json.encode(res)
            end
            return false
        end

        local pre_index = self.values_hash[key]
        if pre_index then
            local pre_val = self.values[pre_index]
            if pre_val and pre_val.clean_handlers then
                for _, clean_handler in ipairs(pre_val.clean_handlers) do
                    clean_handler(pre_val)
                end
                pre_val.clean_handlers = nil
            end
            -- res.value ?????????????????? ??????nil????????????
            if res.value then
                if not self.single_item then
                    res.value.id = key
                end

                self.values[pre_index] = res
                res.clean_handlers = {}
                log.info("update data by key: ", key)

            else
                self.sync_times = self.sync_times + 1
                self.values[pre_index] = false
                self.values_hash[key] = nil
                log.info("delete data by key: ", key)
            end

        elseif res.value then
            -- pre_index ??????????????? res.value???????????? ????????????(res.value)
            res.clean_handlers = {}
            insert_tab(self.values, res)
            self.values_hash[key] = #self.values
            if not self.single_item then
                res.value.id = key
            end

            log.info("insert data by key: ", key)
        end

        -- avoid space waste
        if self.sync_times > 100 then
            local values_original = table.clone(self.values)
            table.clear(self.values)

            for i = 1, #values_original do
                local val = values_original[i]
                if val then
                    table.insert(self.values, val)
                end
            end

            table.clear(self.values_hash)
            log.info("clear stale data in `values_hash` for key: ", key)

            for i = 1, #self.values do
                key = short_key(self, self.values[i].key)
                self.values_hash[key] = i
            end

            self.sync_times = 0
        end

        -- /plugins' filter need to known self.values when it is called
        -- so the filter should be called after self.values set.
        if self.filter then
            self.filter(res)
        end

        self.conf_version = self.conf_version + 1
    end

    return self.values
end
---@return etcd_v2_node
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


function _M.getkey(self, key)
    if not self.running then
        return nil, "stopped"
    end

    return getkey(self.etcd_cli, key)
end


local get_etcd
do
    ---@type resty_etcd_v3_client
    local etcd_cli

    function get_etcd()
        if etcd_cli ~= nil then
            return etcd_cli
        end

        local local_conf, err = config_local.local_conf()
        if not local_conf then
            return nil, err
        end

        local etcd_conf = clone_tab(local_conf.etcd)
        etcd_conf.http_host = etcd_conf.host
        etcd_conf.host = nil
        etcd_conf.prefix = nil
        etcd_conf.protocol = "v3"
        etcd_conf.api_prefix = "/v3"

        -- default to verify etcd cluster certificate
        etcd_conf.ssl_verify = true
        if etcd_conf.tls then
            if etcd_conf.tls.verify == false then
                etcd_conf.ssl_verify = false
            end

            if etcd_conf.tls.cert then
                etcd_conf.ssl_cert_path = etcd_conf.tls.cert
                etcd_conf.ssl_key_path = etcd_conf.tls.key
            end
        end

        local err
        etcd_cli, err = etcd.new(etcd_conf)
        return etcd_cli, err
    end
end

---@param self config_etcd
local function _automatic_fetch(premature, self)
    if premature then
        return
    end

    local i = 0
    while not exiting() and self.running and i <= 32 do
        i = i + 1

        local ok, err = xpcall(function()
            if not self.etcd_cli then
                local etcd_cli, err = get_etcd()
                if not etcd_cli then
                    error("failed to create etcd instance for key ["
                          .. self.key .. "]: " .. (err or "unknown"))
                end
                self.etcd_cli = etcd_cli
            end

            local ok, err = sync_data(self)
            if err then
                if err ~= "timeout" and err ~= "Key not found"
                    and self.last_err ~= err then
                    log.error("failed to fetch data from etcd: ", err, ", ",
                              tostring(self))
                end

                if err ~= self.last_err then
                    self.last_err = err
                    self.last_err_time = ngx_time()
                else
                    if ngx_time() - self.last_err_time >= 30 then
                        self.last_err = nil
                    end
                end

                ngx_sleep(self.resync_delay + rand() * 0.5 * self.resync_delay)
            elseif not ok then
                -- no error. reentry the sync with different state
                ngx_sleep(0.05)
            end

        end, debug.traceback)

        if not ok then
            log.error("failed to fetch data from etcd: ", err, ", ",
                      tostring(self))
            ngx_sleep(self.resync_delay + rand() * 0.5 * self.resync_delay)
            break
        end
    end

    if not exiting() and self.running then
        ngx_timer_at(0, _automatic_fetch, self)
    end
end


function _M.new(key, opts)
    local local_conf, err = config_local.local_conf()
    if not local_conf then
        return nil, err
    end

    local etcd_conf = local_conf.etcd
    local prefix = etcd_conf.prefix
    local resync_delay = etcd_conf.resync_delay
    if not resync_delay or resync_delay < 0 then
        resync_delay = 5
    end

    local automatic = opts and opts.automatic
    local item_schema = opts and opts.item_schema
    local filter_fun = opts and opts.filter
    local timeout = opts and opts.timeout
    local single_item = opts and opts.single_item
    local checker = opts and opts.checker

    local obj = setmetatable({
        etcd_cli = nil,
        key = key and prefix .. key,
        automatic = automatic,
        item_schema = item_schema,
        checker = checker,
        sync_times = 0,
        running = true,
        conf_version = 0,
        values = nil,
        need_reload = true,
        routes_hash = nil,
        prev_index = 0,
        last_err = nil,
        last_err_time = nil,
        resync_delay = resync_delay,
        timeout = timeout,
        single_item = single_item,
        filter = filter_fun,
    }, mt)

    if automatic then
        if not key then
            return nil, "missing `key` argument"
        end

        if loaded_configuration[key] then
            local res = loaded_configuration[key]
            loaded_configuration[key] = nil -- tried to load

            log.notice("use loaded configuration ", key)

            local dir_res, headers = res.body, res.headers
            load_full_data(obj, dir_res, headers)
        end

        ngx_timer_at(0, _automatic_fetch, obj)

    else
        local etcd_cli, err = get_etcd()
        if not etcd_cli then
            return nil, "failed to start a etcd instance: " .. err
        end
        obj.etcd_cli = etcd_cli
    end

    if key then
        created_obj[key] = obj
    end

    return obj
end


function _M.close(self)
    self.running = false
end


function _M.fetch_created_obj(key)
    return created_obj[key]
end


local function read_etcd_version(etcd_cli)
    if not etcd_cli then
        return nil, "not inited"
    end

    local data, err = etcd_cli:version()
    if not data then
        return nil, err
    end

    local body = data.body
    if type(body) ~= "table" then
        return nil, "failed to read response body when try to fetch etcd "
                    .. "version"
    end

    return body
end

---@param self config_etcd
function _M.server_version(self)
    if not self.running then
        return nil, "stopped"
    end

    return read_etcd_version(self.etcd_cli)
end


local function create_formatter(prefix)
    return function (res)
        res.body.nodes = {}

        local dirs
        if is_http then
            dirs = constants.HTTP_ETCD_DIRECTORY
        else
            dirs = constants.STREAM_ETCD_DIRECTORY
        end

        local curr_dir_data
        local curr_key
        for _, item in ipairs(res.body.kvs) do
            if curr_dir_data then
                if core_str.has_prefix(item.key, curr_key) then
                    table.insert(curr_dir_data, etcd_apisix.kvs_to_node(item))
                    goto CONTINUE
                end

                curr_dir_data = nil
            end

            local key = sub_str(item.key, #prefix + 1)
            if dirs[key] then
                -- single item
                loaded_configuration[key] = {
                    body = etcd_apisix.kvs_to_node(item),
                    headers = res.headers,
                }
            else
                local key = sub_str(item.key, #prefix + 1, #item.key - 1)
                -- ensure the same key hasn't been handled as single item
                if dirs[key] and not loaded_configuration[key] then
                    loaded_configuration[key] = {
                        body = {
                            nodes = {},
                        },
                        headers = res.headers,
                    }
                    curr_dir_data = loaded_configuration[key].body.nodes
                    curr_key = item.key
                end
            end

            ::CONTINUE::
        end

        return res
    end
end


function _M.init()
    local local_conf, err = config_local.local_conf()
    if not local_conf then
        return nil, err
    end

    if table.try_read_attr(local_conf, "apisix", "disable_sync_configuration_during_start") then
        return true
    end

    local etcd_cli, err = get_etcd()
    if not etcd_cli then
        return nil, "failed to start a etcd instance: " .. err
    end

    local etcd_conf = local_conf.etcd
    local prefix = etcd_conf.prefix
    local res, err = readdir(etcd_cli, prefix, create_formatter(prefix))
    if not res then
        return nil, err
    end

    return true
end


return _M
