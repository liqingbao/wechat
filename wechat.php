<?php
//微信开发相关接口
//网页授权获取openid && userinfo信息
//微信支付相关
//jssdk相关
class Wechat
{
	//商户号
	public $MCHID;
	// appid
	public $APPID;
	// appsecret
	public $APPSECRET;
	// appkey
	public $KEY;
	
	//LINUX 使用相对路径 物理路径  /www/web/xxx/uploads/2018/04/GqdlOsJgYusF.pem
	//windows服务器上证书路径使用绝对路径。
	public $SSLCERT_PATH;
	public $SSLKEY_PATH;
	public $curl_timeout = 10;

	//保存access_token && jaspi_ticket 文件的路劲 这里用文件存储
	public $access_token_path = './access_token.php';
	public $jsapi_ticket_path = './jsapi_ticket.php';
	function __construct($config = [])
	{
		$this->MCHID = isset($config['mchid']) ? $config['mchid'] : '';
		$this->APPID = isset($config['appid']) ? $config['appid'] : '';
		$this->APPSECRET = isset($config['appsecret']) ? $config['appsecret'] : '';
		$this->KEY = isset($config['appkey']) ? $config['appkey'] : '';
		$this->SSLCERT_PATH = isset($config['sslcert_path']) ? $config['sslcert_path'] : '';
		$this->SSLKEY_PATH = isset($config['sslcert_password']) ? $config['sslcert_password'] : '';
	}

	/**
	 * 
	 * 通过跳转获取用户的openid，跳转流程如下：
	 * 1、设置自己需要调回的url及其其他参数，跳转到微信服务器https://open.weixin.qq.com/connect/oauth2/authorize
	 * 2、微信服务处理完成之后会跳转回用户redirect_uri地址，此时会带上一些参数，如：code
	 * 
	 * @return 用户的信息
	 */
	public function GetUserinfo()
	{
		//通过code获得openid
		if (!isset($_GET['code'])){
			//触发微信返回code码
			$redirectUrl = urlencode('http://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'].$_SERVER['QUERY_STRING']);

			$urlObj["appid"] = $this->APPID;
			$urlObj["redirect_uri"] = "$redirectUrl";
			$urlObj["response_type"] = "code";
			$urlObj["scope"] = "snsapi_userinfo";
			//只获取用户openid snsapi_base
			// $urlObj["scope"] = "snsapi_base";
			$urlObj["state"] = "STATE"."#wechat_redirect";
			$bizString = $this->ToUrlParams($urlObj);
			$url = "https://open.weixin.qq.com/connect/oauth2/authorize?".$bizString;
			Header("Location: $url");
			exit();
		} else {
			//获取code码，以获取openid
		    $code = $_GET['code'];

		    $urlObj["appid"] = $this->APPID;
			$urlObj["secret"] = $this->APPSECRET;
			$urlObj["code"] = $code;
			$urlObj["grant_type"] = "authorization_code";
			$bizString = $this->ToUrlParams($urlObj);
			$url = "https://api.weixin.qq.com/sns/oauth2/access_token?".$bizString;
			$access_info = $this->__curl($url);
			//$openid = $access_info['openid'];
			//根据openid获取用户信息
			return $this->__get_userinfo($access_info);
		}
	}
	/**
	 * 
	 * 拼接签名字符串
	 * @param array $urlObj
	 * 
	 * @return 返回已经拼接好的字符串
	 */
	private function ToUrlParams($urlObj)
	{
		$buff = "";
		foreach ($urlObj as $k => $v)
		{
			if($k != "sign" && $v != "" && !is_array($v)){
				$buff .= $k . "=" . $v . "&";
			}
		}
		
		$buff = trim($buff, "&");
		return $buff;
	}
	public function __get_userinfo($access_info)
	{
		/*{  "access_token":"ACCESS_TOKEN",
				"expires_in":7200,
				"refresh_token":"REFRESH_TOKEN",
				"openid":"OPENID",
				"scope":"SCOPE" }*/
		$access_info = json_decode($access_info, true);
		$url = "https://api.weixin.qq.com/sns/userinfo?access_token={$access_info['access_token']}&openid={$access_info['openid']}&lang=zh_CN";
		$res_json = $this->__curl($url);
		return json_decode($res_json, true);
	}

	//-------------------------------------------------------------------------微信支付--------------------------------------------------------------
	/**
	 * [unifiedOrder 统一下单接口]
	 * @param    [array]     $order [
	 *                              'order_no' => 订单号
	 *                              'total_fee' => 订单金额 单位：分
	 *                              'notify_url' => 支付结果通知url
	 *                              'trade_type' => 支付类型  JSAPI 等等
	 *                              'openid' => 用户openid
	 *                              		]
	 * @return   [type]            [description]
	 */
	public function unifiedOrder($order)
	{
		$params = [
				'appid' => $this->APPID,
				'mch_id' => $this->MCHID,
				'nonce_str' => $this->getNonceStr(),
				'body' => $order['order_no'],
				'out_trade_no' => $order['order_no'],
				'total_fee' => $order['total_fee'],
				'spbill_create_ip' => $_SERVER['REMOTE_ADDR'],
				'notify_url' => $order['notify_url'],
				'trade_type' => $order['trade_type'],
				];
		if(isset($order['openid']))
			$params['openid'] = $order['openid'];
		$params['sign'] = $this->MakeSign($params);
		$xml = $this->ToXml($params);
		$url = "https://api.mch.weixin.qq.com/pay/unifiedorder";
		$response = $this->postXmlCurl($xml, $url);
		$response = $this->FromXml($response);
		return $response;
	}
	/**
	 * [orderquery 订单查询]
	 * @param    [type]     $transaction_id [微信支付交易id]
	 * @return   [type]                     [description]
	 */
	public function orderquery($transaction_id)
	{
		$params = [
					'appid' => $this->APPID,
					'mch_id' => $this->MCHID,
					'transaction_id' => $transaction_id,
					'nonce_str' => $this->getNonceStr(),
				];
		$params['sign'] = $this->MakeSign($params);

		$xml = $this->ToXml($params);
		$url = "https://api.mch.weixin.qq.com/pay/orderquery";
		$response = $this->postXmlCurl($xml, $url);
		$response = $this->FromXml($response);
		return $response;
	}
	//返回通知结果
	public function notify_response($array)
	{
		$xml = $this->ToXml($array);
		echo $xml;
	}
	/**
	 * [refund 退款申请]
	 * @param    [array]     $refund_info [
	 *                                    	'transaction_id' => 微信支付交易id
	 *                                    	'out_refund_no' => 商户退款单号
	 *                                    	'total_fee' => 订单总金额 单位：分
	 *                                    	'refund_fee' => 退款金额 单位：分
	 *                                    	]
	 * @return   [type]                  [description]
	 */
	public function refund($refund_info)
	{
		$params = [
				'appid' => $this->APPID,
				'mch_id' => $this->MCHID,
				'nonce_str' => $this->getNonceStr(),
				'transaction_id' => $refund_info['transaction_id'],
				'out_refund_no' => $refund_info['out_refund_no'],
				'total_fee' => $refund_info['total_fee'],
				'refund_fee' => $refund_info['refund_fee'],
				];
		$params['sign'] = $this->MakeSign($params);

		$xml = $this->ToXml($params);
		$url = "https://api.mch.weixin.qq.com/secapi/pay/refund";
		$response = $this->postXmlCurl($xml, $url, true);
		$response = $this->FromXml($response);
		return $response;
	}
	/**
	 * [getNonceStr description]
	 * @param    [int]     $length [所需字符串长度]
	 * @return   [string]             [生成的字符串]
	 */
	function getNonceStr( $length = 32)
	{
		$letters = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3','4','5','6','7','8','9','_'];
		$letters_length = count($letters);
		$random_str = '';//生成的字符串
		for ($i=0; $i < $length; $i++) {
			$random_str .= $letters[mt_rand(0,$letters_length-1)];
		}
		return $random_str;
	}
	/**
	 * 生成签名
	 * @return 签名，本函数不覆盖sign成员变量，如要设置签名需要调用SetSign方法赋值
	 */
	public function MakeSign($params)
	{
		//签名步骤一：按字典序排序参数
		ksort($params);
		$string = $this->ToUrlParams($params);
		//签名步骤二：在string后加入KEY
		$string = $string . "&key=".$this->KEY;
		//签名步骤三：MD5加密
		$string = md5($string);
		//签名步骤四：所有字符转为大写
		$result = strtoupper($string);
		return $result;
	}
	//-------------------------------------------------------------------------微信支付--------------------------------------------------------------
	//-------------------------------------------------------------------------ACCESS_TOKEN---------------------------------------------------------
	//获取access_token
	public function get_access_token()
	{
		if(file_exists($this->access_token_path))
        {
            $data = json_decode($this->get_php_file($this->access_token_path));
            if ($data->expire_time < time())
            {
                $access_token = $this->access_token_api();
                return $access_token;
            }
            else
            {
                $access_token = $data->access_token;
                return $access_token;
            }
        }
        else
        {
            $access_token = $this->access_token_api();
            return $access_token;
        }
	}
	private function access_token_api()
    {
        $url = 'https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid='.$this->APPID.'&secret='.$this->APPSECRET;
        $res = $this->__curl($url);
        $res = json_decode($res);
        if(!isset($res->expires_in) || !isset($res->access_token))
        {
        	return FALSE;//获取失败
        }
        $data['expire_time'] = time() + $res->expires_in;
        $data['access_token'] = $res->access_token;
        $this->set_php_file($this->access_token_path, json_encode($data));
        return $res->access_token;
    }
	//-------------------------------------------------------------------------ACCESS_TOKEN---------------------------------------------------------
	//---------------------------------------------------------------------获取jsapi_ticket---------------------------------------------------------
    //获取jsapi_ticket
	public function get_jsapi_ticket()
	{
		 if(file_exists($this->jsapi_ticket_path))
        {
            $data = json_decode($this->get_php_file($this->jsapi_ticket_path));
            if ($data->expire_time < time())
            {
                $jsapi_ticket = $this->jsapi_ticket_api();
                return $jsapi_ticket;
            }
            else
            {
                $jsapi_ticket = $data->jsapi_ticket;
                return $jsapi_ticket;
            }
        }
        else
        {
            $jsapi_ticket = $this->jsapi_ticket_api();
            return $jsapi_ticket;
        }
	}
	private function jsapi_ticket_api()
    {
        $access_token = $this->get_access_token();
        $url = 'https://api.weixin.qq.com/cgi-bin/ticket/getticket?type=jsapi&access_token='.$access_token;
        $res = $this->__curl($url);
        // $res = file_get_contents($url);
        $res = json_decode($res);
        if(!isset($res->errcode) && $res->errcode == 0)
        {
        	return FALSE;//获取失败
        }
        $data['expire_time'] = time() + $res->expires_in;
        $data['jsapi_ticket'] = $res->ticket;
        $this->set_php_file($this->jsapi_ticket_path, json_encode($data));
        return $res->ticket;
    }
	//---------------------------------------------------------------------获取jsapi_ticket---------------------------------------------------------
	//---------------------------------------------------------------------获取jsapi_config---------------------------------------------------------
	//jssdk 获取wx.config 信息
    public function getSignPackage()
    {
    	$jsapiTicket = $this->get_jsapi_ticket();

    	// 注意 URL 一定要动态获取，不能 hardcode.
    	$protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
    	$url = "$protocol$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";

    	$timestamp = time();
    	$nonceStr = $this->getNonceStr(16);

    	// 这里参数的顺序要按照 key 值 ASCII 码升序排序
    	$string = "jsapi_ticket=$jsapiTicket&noncestr=$nonceStr&timestamp=$timestamp&url=$url";

    	$signature = sha1($string);

    	$signPackage = array(
    		"appId"     => $this->APPID,
    		"nonceStr"  => $nonceStr,
    		"timestamp" => $timestamp,
    		"url"       => $url,
    		"signature" => $signature,
    		"rawString" => $string
    	);
    	return $signPackage; 
    }
	//---------------------------------------------------------------------获取jsapi_config---------------------------------------------------------
	private function get_php_file($filename)
    {
        return trim(substr(file_get_contents($filename), 15));
    }
    private function set_php_file($filename, $content)
    {
    	file_put_contents($filename, "<?php exit();?>" . $content);
    }
	/**
	 * 输出xml字符
	 * @throws WxPayException
	**/
	public function ToXml($array = [])
	{
		if( ! is_array($array) 
			|| count($array) <= 0)
		{
    		throw new Exception("数组数据异常！");
    	}
    	
    	$xml = "<xml>";
    	foreach ($array as $key=>$val)
    	{
    		if (is_numeric($val)){
    			$xml.="<".$key.">".$val."</".$key.">";
    		}else{
    			$xml.="<".$key."><![CDATA[".$val."]]></".$key.">";
    		}
        }
        $xml.="</xml>";
        return $xml; 
	}
	
    /**
     * 将xml转为array
     * @param string $xml
     * @throws WxPayException
     */
	public function FromXml($xml)
	{	
		if(!$xml){
			throw new Exception("xml数据异常！");
		}
        //将XML转为array
        //禁止引用外部xml实体
        libxml_disable_entity_loader(true);
        return json_decode(json_encode(simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOCDATA)), true);		
	}








	/**
	 * 以post方式提交xml到对应的接口url
	 * 
	 * @param string $xml  需要post的xml数据
	 * @param string $url  url
	 * @param bool $useCert 是否需要证书，默认不需要
	 * @param int $second   url执行超时时间，默认30s
	 * @throws WxPayException
	 */
	private function postXmlCurl($xml, $url, $useCert = false, $second = 30)
	{		
		$ch = curl_init();
		//设置超时
		curl_setopt($ch, CURLOPT_TIMEOUT, $second);
		
		curl_setopt($ch,CURLOPT_URL, $url);
		
		curl_setopt($ch,CURLOPT_SSL_VERIFYPEER,FALSE);
		curl_setopt($ch,CURLOPT_SSL_VERIFYHOST,FALSE);//严格校验2
		//设置header
		curl_setopt($ch, CURLOPT_HEADER, FALSE);
		//要求结果为字符串且输出到屏幕上
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
		
		if($useCert == true){
			//设置证书
			//使用证书：cert 与 key 分别属于两个.pem文件
			curl_setopt($ch,CURLOPT_SSLCERTTYPE,'PEM');
			curl_setopt($ch,CURLOPT_SSLCERT, $this->SSLCERT_PATH);
			curl_setopt($ch,CURLOPT_SSLKEYTYPE,'PEM');
			curl_setopt($ch,CURLOPT_SSLKEY, $this->SSLKEY_PATH);
		}
		//post提交方式
		curl_setopt($ch, CURLOPT_POST, TRUE);
		curl_setopt($ch, CURLOPT_POSTFIELDS, $xml);
		//运行curl
		$data = curl_exec($ch);
		
		//返回结果
		if($data){
			curl_close($ch);
			return $data;
		} else { 
			$error = curl_errno($ch);
			curl_close($ch);
			throw new Exception("curl出错，错误码:$error");
		}
	}

	private function __curl($url = '', $post = array())
 	{
 		$ch = curl_init();
 		curl_setopt ( $ch, CURLOPT_URL, $url );
		curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, TRUE );
		curl_setopt ( $ch, CURLOPT_HEADER, FALSE );
		if(strpos( $url ,'https') !== FALSE)
		{
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
        	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);
		}
 		if (!empty($post)) {
			curl_setopt ( $ch, CURLOPT_POST, TRUE );
			curl_setopt ( $ch, CURLOPT_POSTFIELDS, $post);
 		}
 		curl_setopt($ch, CURLOPT_TIMEOUT, $this->curl_timeout);
		$output = curl_exec ( $ch );
		curl_close ( $ch );
		return $output;
 	}
}
