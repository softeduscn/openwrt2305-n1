m = Map("sysmonitor",translate("VPN Nodes"))
s = m:section(TypedSection, "sysmonitor", "")
--s.description = '<table><tr><td title="Update VPN nodes"><button class="button1"><a href="/cgi-bin/luci/admin/sys/sysmonitor/sysmenu?sys=Updatenodesys1=&redir=node">' .. translate("UpdateNODE") .. '</a></button></td></tr></table>'
s.anonymous = true

f = SimpleForm("sysmonitor")
f.reset = false
f.submit = false
f:append(Template("sysmonitor/node"))
return m,  f
