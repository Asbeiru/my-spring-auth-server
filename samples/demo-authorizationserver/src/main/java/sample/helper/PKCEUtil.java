package sample.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class PKCEUtil {
	public static void main(String[] args) {
		// 生成 code_verifier
		String codeVerifier = generateCodeVerifier();
		System.out.println("Code Verifier: " + codeVerifier);

		// 生成 code_challenge
		String codeChallenge = generateCodeChallenge(codeVerifier);
		System.out.println("Code Challenge: " + codeChallenge);

		System.out.println("\n=== 第一步：获取授权码 ===");
		// 打印完整的授权请求URL
		String authorizationRequest = String.format(
				"http://localhost:9001/oauth2/authorize?" +
						"response_type=code" +
						"&client_id=messaging-client" +
						"&scope=openid%%20profile%%20message.read" +
						"&redirect_uri=http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc" +
						"&code_challenge=%s" +
						"&code_challenge_method=S256",
				codeChallenge
		);
		System.out.println("在浏览器中访问以下URL:");
		System.out.println(authorizationRequest);

		System.out.println("\n=== 第二步：使用授权码获取令牌 ===");
		System.out.println("使用 Postman 发送 POST 请求:");
		System.out.println("URL: http://localhost:9001/oauth2/token");
		System.out.println("Headers:");
		System.out.println("  Content-Type: application/x-www-form-urlencoded");
		System.out.println("  Authorization: Basic bWVzc2FnaW5nLWNsaWVudDpzZWNyZXQ=");
		System.out.println("Body (x-www-form-urlencoded):");
		System.out.println("  grant_type=authorization_code");
		System.out.println("  code=<授权码>");
		System.out.println("  redirect_uri=http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc");
		System.out.println("  code_verifier=" + codeVerifier);

		System.out.println("\n=== 第三步：使用访问令牌调用资源服务器 ===");
		System.out.println("1. 获取用户信息");
		System.out.println("使用 Postman 发送 GET 请求:");
		System.out.println("URL: http://localhost:9001/userinfo");
		System.out.println("Headers:");
		System.out.println("  Authorization: Bearer <access_token>");

		System.out.println("\n2. 访问消息资源");
		System.out.println("使用 Postman 发送 GET 请求:");
		System.out.println("URL: http://localhost:8090/messages");
		System.out.println("Headers:");
		System.out.println("  Authorization: Bearer <access_token>");

		System.out.println("\n=== 第四步：刷新令牌（可选）===");
		System.out.println("使用 Postman 发送 POST 请求:");
		System.out.println("URL: http://localhost:9001/oauth2/token");
		System.out.println("Headers:");
		System.out.println("  Content-Type: application/x-www-form-urlencoded");
		System.out.println("  Authorization: Basic bWVzc2FnaW5nLWNsaWVudDpzZWNyZXQ=");
		System.out.println("Body (x-www-form-urlencoded):");
		System.out.println("  grant_type=refresh_token");
		System.out.println("  refresh_token=<refresh_token>");

		System.out.println("\n注意事项：");
		System.out.println("1. <access_token> 替换为获取到的访问令牌");
		System.out.println("2. <refresh_token> 替换为获取到的刷新令牌");
		System.out.println("3. 令牌响应中还包含 id_token，可用于获取用户信息");
		System.out.println("4. 所有令牌都有过期时间，注意查看令牌响应中的 expires_in 字段");
	}

	public static String generateCodeVerifier() {
		SecureRandom secureRandom = new SecureRandom();
		byte[] codeVerifier = new byte[32];
		secureRandom.nextBytes(codeVerifier);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifier);
	}

	public static String generateCodeChallenge(String codeVerifier) {
		try {
			byte[] bytes = codeVerifier.getBytes(StandardCharsets.US_ASCII);
			MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
			messageDigest.update(bytes);
			byte[] digest = messageDigest.digest();
			return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}
}
