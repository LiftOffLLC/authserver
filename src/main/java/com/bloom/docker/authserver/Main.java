package com.bloom.docker.authserver;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.eclipse.egit.github.core.User;
import org.eclipse.egit.github.core.client.GitHubClient;
import org.eclipse.egit.github.core.client.RequestException;
import org.eclipse.egit.github.core.service.OrganizationService;
import org.eclipse.egit.github.core.service.UserService;

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

import static spark.Spark.*;

/**
 * Created by paggarwal on 1/7/16.
 */
public class Main {

    private static final PrimitiveIterator.OfLong randomStream = new Random().longs().iterator();

    private static final DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");

    public static final String KEY_STORE = System.getenv("KEY_STORE");

    public static final String KEY_STORE_PASSWORD = System.getenv("KEY_STORE_PASSWORD");

    public static final String KEY_ID = System.getenv("KEY_ID"); //"DF63:MN25:ABEN:ZYXG:5KZA:OMSH:5EXI:OFDR:X6YT:ZMRF:RVEL:JBOM"

    public static final List<String> GITHUB_ORG = Arrays.asList(System.getenv("GITHUB_ORG").split(",")); // "LiftOffLLC"

    public static final List<String> GITHUB_USERS = Arrays.asList(System.getenv("GITHUB_USERS").split(","));

    public static final String AUDIENCE = System.getenv("AUDIENCE");

    public static final String ISSUER = System.getenv("ISSUER");

    private static final Key KEY;

    static {
        try {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(new FileInputStream(KEY_STORE), KEY_STORE_PASSWORD.toCharArray());
            KEY = keystore.getKey("selfsigned", KEY_STORE_PASSWORD.toCharArray());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static {
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    }

    public static void main(String... args) {
        port(8443);
        secure(KEY_STORE, KEY_STORE_PASSWORD, null, null);

        get("/auth", (req, res) -> {
            Set<String> queryParams = req.queryParams();
            if (queryParams.contains("account") && req.headers().contains("Authorization")) {
                String usernamePass = new String(Base64.getDecoder().decode(req.headers("Authorization").split(" ")[1]));
                String username = usernamePass.split(":")[0];
                String pass = usernamePass.split(":")[1];
                GitHubClient client = new GitHubClient();
                client.setCredentials(username, pass);
                OrganizationService organizationService = new OrganizationService(client);
                UserService userService = new UserService(client);
                try {
                    if (!GITHUB_USERS.contains(userService.getUser().getLogin())) {
                        List<User> organizations = organizationService.getOrganizations();
                        if (!organizations.stream().filter(user1 -> GITHUB_ORG.contains(user1.getLogin())).findFirst().isPresent()) {
                            halt(401);
                        }
                    }
                } catch (RequestException e) {
                    res.status(e.getStatus());
                    halt(e.getStatus());
                }
                String token = token(username, req.queryParams("scope"));
                res.status(200);
                res.type("application/json");
                res.body(token);
                return token;
            } else {
                halt(401);
                return "{}";
            }
        });
    }

    private static String token(String account, String scope) {
        Date issuedAt = new Date();
        Date expiration = new Date(issuedAt.getTime() + 60000);
        Date notBefore = new Date(issuedAt.getTime() - 2000);

        JwtBuilder builder = Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setHeaderParam("kid", KEY_ID);

        if (scope != null && scope.trim().length() > 0) {
            builder.setClaims(getClaims(scope));
        }

        String s = builder.setAudience(AUDIENCE)
                .setExpiration(expiration)
                .setIssuedAt(issuedAt)
                .setNotBefore(notBefore)
                .setId(randomStream.next().toString())
                .setSubject(account)
                .setIssuer(ISSUER)
                .signWith(SignatureAlgorithm.RS256, KEY).compact();

        return "{\"token\":" +
                "\"" + s + "\", \"access_token\": \"" + s + "\", \"expires_in\":" +
                "\"3600\", \"issued_at\":\"" + dateFormat.format(issuedAt) + "\"}";
    }

    private static Map<String, Object> getClaims(String scope) {
        Map<String, Object> claims = new HashMap<>();


        List<Object> list = new ArrayList<>();

        for (String entry : scope.split(" ")) {
            Map<String, Object> entryMap = new HashMap<>();
            entryMap.put("type", entry.split(":")[0]);
            entryMap.put("name", entry.split(":")[1]);

            List<String> actions = new ArrayList<>();
            for (String action : entry.split(":")[2].split(",")) {
                actions.add(action);
            }
            entryMap.put("actions", actions);
            list.add(entryMap);

        }
        claims.put("access", list);

        return claims;
    }
}
