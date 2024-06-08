local datatypes = require "luci.cbi.datatypes"

local ipv4_list_file = "/etc/smartdns/domain-set/ipv4list"
--local block_list_file = "/etc/smartdns/domain-set/blocklist"

m = Map("sysmonitor")

s = m:section(TypedSection, "sysmonitor", translate("Rule Settings"))
s.anonymous = true

s:tab("ipv4_list", translate("Domain IPv4-Lists"))
--s:tab("block_list", translate("Block Lists"))

o = s:taboption("ipv4_list", TextValue, "ipv4list", "", "<font color='red'>" .. translate("These domain names allow DNS return only ipv4 address . Please input the domain names, every line can input only one domain. For example: baidu.com.") .. "</font>" .. "</font>")
o.rows = 15
o.wrap = "off"
o.cfgvalue = function(self, section) return nixio.fs.readfile(ipv4_list_file) or "" end
o.write = function(self, section, value) nixio.fs.writefile(ipv4_list_file , value:gsub("\r\n", "\n")) end
o.remove = function(self, section, value) nixio.fs.writefile(ipv4_list_file , "") end
o.validate = function(self, value)
    return value
end

--[[o = s:taboption("block_list", TextValue, "blocklist", "", "<font color='red'>" .. translate("These domains are blocked from DNS resolution. Please input the domain names, every line can input only one domain. For example: baidu.com.") .. "</font>" .. "<font color='#00bd3e'>" .. translate("<br>The list of rules only apply to 'Default Config' profiles.") .. "</font>")
o.rows = 15
o.wrap = "off"
o.cfgvalue = function(self, section) return nixio.fs.readfile(block_list_file) or "" end
o.write = function(self, section, value) nixio.fs.writefile(block_list_file, value:gsub("\r\n", "\n")) end
o.remove = function(self, section, value) nixio.fs.writefile(block_list_file, "") end
o.validate = function(self, value)
    return value
end
]]--

local apply = luci.http.formvalue("cbi.apply")
if apply then
    luci.sys.exec("/etc/init.d/smartdns reload")
end

return m
