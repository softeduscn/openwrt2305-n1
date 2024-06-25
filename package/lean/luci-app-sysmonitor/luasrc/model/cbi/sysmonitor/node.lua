nextvpn=luci.sys.exec("uci get sysmonitor.sysmonitor.nextvpn")
m = Map("sysmonitor",translate("VPN Nodes"))
s = m:section(TypedSection, "sysmonitor", "")
if tonumber(nextvpn) == 1 then
	box=' <input type="checkbox" checked="checked" />'
	check='Disable switch VPN'
else
	box=' <input type="checkbox" />'
	check='Enable switch VPN'	
end
s.description = '<table><style>.button1 {-webkit-transition-duration: 0.4s;transition-duration: 0.4s;padding: 1px 3px;text-align: center;background-color: white;color: black;border: 2px solid #4CAF50;border-radius:5px;}.button1:hover {background-color: #4CAF50;color: white;}.button1 {font-size: 11px;}</style><tr><td><button class="button1" title="Set switch VPN mode"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=VPNswitch&sys1=&redir=node">'..translate(check)..'</a></button>'..box
s.anonymous = true

f = SimpleForm("sysmonitor")
f.reset = false
f.submit = false
f:append(Template("sysmonitor/node"))
return m,  f
