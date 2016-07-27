-- 导入类库
local Guard = require "guard"
-- 获取remote_addr
local remoteIp = ngx.var.remote_addr
-- 获取 headers
local headers = ngx.req.get_headers()
-- 判断获取客户端真实IP
local ip = Guard:getRealIp(remoteIp,headers)
-- 判断获取请求uri
local reqUri = ngx.var.request_uri
-- uri
local uri = ngx.var.uri
local address = ''

-- 导入nginx模块
local limitModule = ngx.var.limit_module
local redirectModule = ngx.var.redirect_module
local jsModule = ngx.var.js_module
local cookieModule = ngx.var.cookie_module

--判断是某种url匹配模式
-- 值requestUri时,url-protect目录下的正则匹配的是浏览器最初请求的地址且没有被decode,带参数的链接
-- 值为uri时, url-protect目录下的正则匹配的是经过重写过的地址,不带参数,且已经decode.
if _Conf.uriMode then
	address = uri
elseif _Conf.requestUriMode then
	address = reqUri
end	


--获取验证码
if ngx.re.match(uri,"/get-captcha.jpg$","i") then
	Guard:getCaptcha()

--验证验证码
elseif ngx.re.match(uri,"/verify-captcha.jpg$","i") then
	Guard:verifyCaptcha(ip)

--过滤请求
else
	--定时检查连接数
	if _Conf.autoEnableIsOn then
		ngx.timer.at(0,Guard.autoSwitch)
	end
		
	--白名单模块 -- 匹配到白名单，返回true; 没有匹配到返回false
	if not Guard:ipInWhiteList(ip) then
		--黑名单模块 --执行相应的动作
		Guard:blackListModules(ip,reqUri)

		--限制请求速率模块
		if _Conf.limitReqModulesIsOn then --limitReq模块是否开启
			if not (limitModule == "off") then
				Guard:debug("[limitReqModules] limitReqModules is on.",ip,reqUri)
				Guard:limitReqModules(ip,reqUri,address)
			end
		elseif limitModule == "on" then
			Guard:debug("[limitReqModules] limitReqModules is on.",ip,reqUri)
			Guard:limitReqModules(ip,reqUri,address)
		end

		--302转向模块
		local redirectOn = _Conf.dict_captcha:get("redirectOn")
		if redirectOn == 1 then --判断转向模块是否开启
			if not (redirectModule == "off") then
				Guard:debug("[redirectModules] redirectModules is on.",ip,reqUri)
				Guard:redirectModules(ip,reqUri,address)
			end
		elseif redirectModule == "on" then
			Guard:debug("[redirectModules] redirectModules is on.",ip,reqUri)
			Guard:redirectModules(ip,reqUri,address)		 		
		end	

		--js跳转模块
		local jsOn = _Conf.dict_captcha:get("jsOn")
		if jsOn == 1 then --判断js跳转模块是否开启
			if not (jsModule == "off") then
				Guard:debug("[JsJumpModules] JsJumpModules is on.",ip,reqUri)
				Guard:JsJumpModules(ip,reqUri,address)
			end
		elseif jsModule == "on" then
			Guard:debug("[JsJumpModules] JsJumpModules is on.",ip,reqUri)
			Guard:JsJumpModules(ip,reqUri,address)				
		end

		--cookie验证模块
		local cookieOn = _Conf.dict_captcha:get("cookieOn")
		if cookieOn == 1 then --判断是否开启cookie模块
			if not (cookieModule == "off") then
				Guard:debug("[cookieModules] cookieModules is on.",ip,reqUri)
				Guard:cookieModules(ip,reqUri,address)
			end
		elseif cookieModule == "on" then
			Guard:debug("[cookieModules] cookieModules is on.",ip,reqUri)
			Guard:cookieModules(ip,reqUri,address)				
		end
			
	end	
end

