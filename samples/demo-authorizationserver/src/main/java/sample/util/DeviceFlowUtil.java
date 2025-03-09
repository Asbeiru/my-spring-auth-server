package sample.util;

public class DeviceFlowUtil {
    public static void main(String[] args) {
        System.out.println("=== OAuth 2.0 设备码授权流程测试步骤 ===\n");

        System.out.println("第一步：获取设备码和用户码");
        System.out.println("使用 Postman 发送 POST 请求:");
        System.out.println("URL: http://localhost:9001/oauth2/device_authorization");
        System.out.println("Headers:");
        System.out.println("  Content-Type: application/x-www-form-urlencoded");
        System.out.println("  Authorization: Basic bWVzc2FnaW5nLWNsaWVudDpzZWNyZXQ=");
        System.out.println("Body (x-www-form-urlencoded):");
        System.out.println("  scope=openid profile message.read\n");
        System.out.println("响应示例：");
        System.out.println("{\n" +
                "    \"device_code\": \"设备验证码\",\n" +
                "    \"user_code\": \"用户输入码\",\n" +
                "    \"verification_uri\": \"http://localhost:9001/activate\",\n" +
                "    \"verification_uri_complete\": \"http://localhost:9001/activate?user_code=用户输入码\",\n" +
                "    \"expires_in\": 300,\n" +
                "    \"interval\": 5\n" +
                "}\n");

        System.out.println("第二步：用户验证");
        System.out.println("1. 在浏览器中打开 verification_uri_complete URL");
        System.out.println("2. 用户登录并授权应用程序访问请求的范围\n");

        System.out.println("第三步：轮询获取访问令牌");
        System.out.println("使用 Postman 发送 POST 请求:");
        System.out.println("URL: http://localhost:9001/oauth2/token");
        System.out.println("Headers:");
        System.out.println("  Content-Type: application/x-www-form-urlencoded");
        System.out.println("  Authorization: Basic bWVzc2FnaW5nLWNsaWVudDpzZWNyZXQ=");
        System.out.println("Body (x-www-form-urlencoded):");
        System.out.println("  grant_type=urn:ietf:params:oauth:grant-type:device_code");
        System.out.println("  device_code=<设备验证码>\n");

        System.out.println("可能的响应状态：");
        System.out.println("1. 授权待定 (HTTP 400):");
        System.out.println("{\n" +
                "    \"error\": \"authorization_pending\",\n" +
                "    \"error_description\": \"等待用户授权\"\n" +
                "}\n");

        System.out.println("2. 授权成功 (HTTP 200):");
        System.out.println("{\n" +
                "    \"access_token\": \"访问令牌\",\n" +
                "    \"token_type\": \"Bearer\",\n" +
                "    \"expires_in\": 300,\n" +
                "    \"refresh_token\": \"刷新令牌\",\n" +
                "    \"scope\": \"openid profile message.read\"\n" +
                "}\n");

        System.out.println("第四步：使用访问令牌");
        System.out.println("1. 获取用户信息");
        System.out.println("使用 Postman 发送 GET 请求:");
        System.out.println("URL: http://localhost:9001/userinfo");
        System.out.println("Headers:");
        System.out.println("  Authorization: Bearer <access_token>\n");

        System.out.println("2. 访问消息资源");
        System.out.println("使用 Postman 发送 GET 请求:");
        System.out.println("URL: http://localhost:8090/messages");
        System.out.println("Headers:");
        System.out.println("  Authorization: Bearer <access_token>\n");

        System.out.println("注意事项：");
        System.out.println("1. Basic 认证头的值是 messaging-client:secret 的 Base64 编码");
        System.out.println("2. 轮询间隔要遵循响应中的 interval 参数（默认5秒）");
        System.out.println("3. 设备码和用户码在 expires_in 秒后过期（默认300秒）");
        System.out.println("4. 如果用户拒绝授权，会收到 access_denied 错误");
        System.out.println("5. 如果轮询太频繁，会收到 slow_down 错误");
    }
} 