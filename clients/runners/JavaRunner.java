// Runs a batch of calls through one generated Java client (openapi-generator, okhttp-gson library).
//
// Usage: java -cp <client jar>:<client lib>/* JavaRunner.java <base url> <api package> <client jar> <calls.json> <out.json>
// calls.json: [{"id", "operationId", "params": {spec name: value}, "specNames": [...], "body": json or null,
//               "auth": "<Authorization header>", "headers": {name: value}}]
// A params value {"__file__": name, "content", "type"} is a file part: it becomes a java.io.File of that name.
// The body goes to the one method parameter that is not a spec parameter, turned into its model type by the
// client's own JSON (Gson) setup.
// out.json:   [{"id", "status", "headers", "body", "client_error"}]
//
// The operation is found by its operationId among the client's *Api classes and called with its
// parameters matched by name (the clients are compiled with -parameters). An interceptor keeps the raw
// response, so a 2xx answer the client's strict models reject is still recorded with status and body.
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import okhttp3.OkHttpClient;
import okhttp3.Response;

public class JavaRunner {
    static String norm(String s) {
        return s.replaceAll("[^A-Za-z0-9]", "").toLowerCase();
    }

    public static void main(String[] a) throws Exception {
        String base = a[0], apiPackage = a[1];
        List<Class<?>> apis = new ArrayList<>();
        try (JarFile jf = new JarFile(a[2])) {
            String prefix = apiPackage.replace('.', '/') + "/";
            for (JarEntry e : Collections.list(jf.entries())) {
                String n = e.getName();
                if (n.startsWith(prefix) && n.endsWith("Api.class") && !n.substring(prefix.length()).contains("/")) {
                    apis.add(Class.forName(n.replace('/', '.').replace(".class", "")));
                }
            }
        }
        Class<?> clientCls = Class.forName(apiPackage.substring(0, apiPackage.lastIndexOf('.')) + ".ApiClient");
        JsonArray calls = JsonParser.parseString(Files.readString(Path.of(a[3]))).getAsJsonArray();
        List<Map<String, Object>> out = new ArrayList<>();
        for (JsonElement el : calls) {
            out.add(run(el.getAsJsonObject(), base, apis, clientCls));
        }
        Files.writeString(Path.of(a[4]), new Gson().toJson(out));
    }

    static Map<String, Object> run(JsonObject c, String base, List<Class<?>> apis, Class<?> clientCls) {
        Map<String, Object> res = new LinkedHashMap<>();
        res.put("id", c.get("id").getAsString());
        Map<String, Object> seen = new HashMap<>();
        try {
            Method target = null;
            for (Class<?> api : apis) {
                for (Method m : api.getMethods()) {
                    if (norm(m.getName()).equals(norm(c.get("operationId").getAsString()))) target = m;
                }
                if (target != null) break;
            }
            if (target == null) throw new IllegalStateException("operationId " + c.get("operationId") + " not found in generated client");

            Object client = clientCls.getConstructor().newInstance();
            clientCls.getMethod("setBasePath", String.class).invoke(client, base);
            clientCls.getMethod("addDefaultHeader", String.class, String.class).invoke(client, "Authorization", c.get("auth").getAsString());
            if (c.has("headers")) {
                for (Map.Entry<String, JsonElement> h : c.getAsJsonObject("headers").entrySet()) {
                    clientCls.getMethod("addDefaultHeader", String.class, String.class).invoke(client, h.getKey(), h.getValue().getAsString());
                }
            }
            OkHttpClient http = ((OkHttpClient) clientCls.getMethod("getHttpClient").invoke(client)).newBuilder()
                .addInterceptor(chain -> {
                    Response r = chain.proceed(chain.request());
                    seen.put("status", r.code());
                    Map<String, String> headers = new LinkedHashMap<>();
                    r.headers().toMultimap().forEach((k, v) -> headers.put(k, String.join(", ", v)));
                    seen.put("headers", headers);
                    seen.put("body", r.peekBody(20_000_000L).string());
                    return r;
                }).build();
            clientCls.getMethod("setHttpClient", OkHttpClient.class).invoke(client, http);

            JsonObject params = c.getAsJsonObject("params");
            Map<String, JsonElement> byName = new HashMap<>();
            params.entrySet().forEach(e -> byName.put(norm(e.getKey()), e.getValue()));
            java.util.Set<String> specNames = new java.util.HashSet<>();
            if (c.has("specNames")) c.getAsJsonArray("specNames").forEach(x -> specNames.add(norm(x.getAsString())));
            JsonElement body = c.has("body") ? c.get("body") : null;
            Parameter[] ps = target.getParameters();
            Object[] args = new Object[ps.length];
            for (int i = 0; i < ps.length; i++) {
                JsonElement v = byName.get(norm(ps[i].getName()));
                if (v == null && body != null && !body.isJsonNull() && !specNames.contains(norm(ps[i].getName()))) {
                    Object gson = Class.forName(clientCls.getPackageName() + ".JSON").getMethod("getGson").invoke(null);
                    args[i] = ((Gson) gson).fromJson(body, ps[i].getParameterizedType());
                    body = null;
                    continue;
                }
                args[i] = v == null || v.isJsonNull() ? null : convert(v, ps[i].getParameterizedType());
            }
            if (body != null && !body.isJsonNull()) throw new IllegalStateException("the generated method takes no request body");
            Object api = target.getDeclaringClass().getConstructor(clientCls).newInstance(client);
            String error = null;
            try {
                target.invoke(api, args);
            } catch (InvocationTargetException e) {
                Throwable t = e.getCause();
                int status = seen.containsKey("status") ? (Integer) seen.get("status") : 0;
                // A non-2xx answer is the client reporting the HTTP status; anything else is the client refusing.
                if (status < 300) error = t.getClass().getSimpleName() + ": " + t.getMessage();
            }
            res.put("status", seen.get("status"));
            res.put("headers", seen.getOrDefault("headers", Map.of()));
            res.put("body", seen.getOrDefault("body", ""));
            res.put("client_error", error);
        } catch (Exception e) {
            Throwable t = e instanceof InvocationTargetException ? e.getCause() : e;
            res.put("status", seen.get("status"));
            res.put("headers", seen.getOrDefault("headers", Map.of()));
            res.put("body", seen.getOrDefault("body", ""));
            res.put("client_error", t.getClass().getSimpleName() + ": " + t.getMessage());
        }
        return res;
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    static Object convert(JsonElement v, Type t) throws Exception {
        Class<?> raw = (Class<?>) (t instanceof ParameterizedType pt ? pt.getRawType() : t);
        if (List.class.isAssignableFrom(raw)) {
            Type item = ((ParameterizedType) t).getActualTypeArguments()[0];
            List list = new ArrayList();
            if (v.isJsonArray()) {
                for (JsonElement x : v.getAsJsonArray()) list.add(convert(x, item));
            } else {
                list.add(convert(v, item));
            }
            return list;
        }
        if (v.isJsonObject() && v.getAsJsonObject().has("__file__")) {
            JsonObject f = v.getAsJsonObject();
            Path dir = Files.createTempDirectory("lab-file");
            Path file = dir.resolve(f.get("__file__").getAsString());
            Files.writeString(file, f.get("content").getAsString());
            file.toFile().deleteOnExit();
            dir.toFile().deleteOnExit();
            if (raw == java.io.File.class) return file.toFile();
            return f.get("content").getAsString();
        }
        String s = v.isJsonPrimitive() ? v.getAsString() : v.toString();
        if (raw == String.class) return s;
        if (raw == Integer.class || raw == int.class) return Integer.valueOf(s);
        if (raw == Long.class || raw == long.class) return Long.valueOf(s);
        if (raw == Boolean.class || raw == boolean.class) return Boolean.valueOf(s);
        if (raw == java.math.BigDecimal.class) return new java.math.BigDecimal(s);
        if (raw.isEnum()) return raw.getMethod("fromValue", String.class).invoke(null, s);
        return s;
    }
}
