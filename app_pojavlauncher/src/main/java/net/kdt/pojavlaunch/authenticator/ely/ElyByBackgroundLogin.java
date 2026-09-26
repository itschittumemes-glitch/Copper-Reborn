package net.kdt.pojavlaunch.authenticator.ely;

import static net.kdt.pojavlaunch.PojavApplication.sExecutorService;

import android.util.Log;

import androidx.annotation.Nullable;

import com.kdt.mcgui.ProgressLayout;

import net.kdt.pojavlaunch.R;
import net.kdt.pojavlaunch.Tools;
import net.kdt.pojavlaunch.authenticator.listener.DoneListener;
import net.kdt.pojavlaunch.authenticator.listener.ErrorListener;
import net.kdt.pojavlaunch.authenticator.listener.ProgressListener;
import net.kdt.pojavlaunch.value.MinecraftAccount;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * Ely.by authentication handler
 * Ely.by is a free alternative to Microsoft authentication for Minecraft
 */
public class ElyByBackgroundLogin {
    private static final String TAG = "ElyByAuth";
    private static final String ELY_BY_AUTH_URL = "https://authserver.ely.by/auth/authenticate";
    private static final String ELY_BY_VALIDATE_URL = "https://authserver.ely.by/auth/validate";
    private static final String ELY_BY_REFRESH_URL = "https://authserver.ely.by/auth/refresh";

    private final String mUsername;
    private final String mPassword;
    private final boolean mIsRefresh;
    private final String mRefreshToken;

    /* Fields used to fill the account */
    public String mcName;
    public String mcToken;
    public String mcUuid;
    public String mcRefreshToken;
    public long expiresAt;

    public ElyByBackgroundLogin(String username, String password) {
        this.mUsername = username;
        this.mPassword = password;
        this.mIsRefresh = false;
        this.mRefreshToken = null;
    }

    public ElyByBackgroundLogin(String refreshToken) {
        this.mUsername = null;
        this.mPassword = null;
        this.mIsRefresh = true;
        this.mRefreshToken = refreshToken;
    }

    /**
     * Performs a full login, calling back listeners appropriately
     */
    public void performLogin(@Nullable final ProgressListener progressListener,
                             @Nullable final DoneListener doneListener,
                             @Nullable final ErrorListener errorListener) {
        sExecutorService.execute(() -> {
            try {
                notifyProgress(progressListener, 1);
                
                JSONObject response;
                if (mIsRefresh) {
                    response = refreshToken();
                } else {
                    response = authenticate(mUsername, mPassword);
                }

                notifyProgress(progressListener, 2);

                // Parse response
                mcToken = response.getString("accessToken");
                mcRefreshToken = response.getString("refreshToken");
                
                JSONObject profile = response.getJSONObject("selectedProfile");
                mcName = profile.getString("name");
                mcUuid = profile.getString("id");

                // Ely.by tokens last 24 hours by default
                expiresAt = System.currentTimeMillis() + 86400000;

                notifyProgress(progressListener, 3);

                MinecraftAccount acc = MinecraftAccount.load(mcName);
                if (acc == null) acc = new MinecraftAccount();
                
                acc.username = mcName;
                acc.profileId = mcUuid;
                acc.accessToken = mcToken;
                acc.clientToken = "ely.by";
                acc.isMicrosoft = false;
                acc.msaRefreshToken = mcRefreshToken;
                acc.expiresAt = expiresAt;
                acc.updateSkinFace();
                acc.save();

                if (doneListener != null) {
                    MinecraftAccount finalAcc = acc;
                    Tools.runOnUiThread(() -> doneListener.onLoginDone(finalAcc));
                }

            } catch (Exception e) {
                Log.e(TAG, "Exception thrown during authentication", e);
                if (errorListener != null) {
                    Tools.runOnUiThread(() -> errorListener.onLoginError(e));
                }
            }
            ProgressLayout.clearProgress(ProgressLayout.AUTHENTICATE_MICROSOFT);
        });
    }

    /**
     * Authenticate with username and password
     */
    private JSONObject authenticate(String username, String password) throws IOException, JSONException, ProtocolException {
        URL url = new URL(ELY_BY_AUTH_URL);

        JSONObject data = new JSONObject();
        data.put("username", username);
        data.put("password", password);
        data.put("clientToken", "Copper-Android");
        data.put("requestUser", true);

        String request = data.toString();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        setCommonProperties(conn, request);
        conn.connect();

        try (OutputStream wr = conn.getOutputStream()) {
            wr.write(request.getBytes(StandardCharsets.UTF_8));
        }

        if (conn.getResponseCode() >= 200 && conn.getResponseCode() < 300) {
            JSONObject response = new JSONObject(Tools.read(conn.getInputStream()));
            conn.disconnect();
            Log.i(TAG, "Authentication successful");
            return response;
        } else if (conn.getResponseCode() == 403) {
            throw new RuntimeException("Invalid username or password");
        } else {
            throw new RuntimeException("Authentication failed: " + conn.getResponseMessage());
        }
    }

    /**
     * Refresh access token using refresh token
     */
    private JSONObject refreshToken() throws IOException, JSONException, ProtocolException {
        URL url = new URL(ELY_BY_REFRESH_URL);

        JSONObject data = new JSONObject();
        data.put("accessToken", mRefreshToken);
        data.put("clientToken", "Copper-Android");
        data.put("requestUser", true);

        String request = data.toString();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        setCommonProperties(conn, request);
        conn.connect();

        try (OutputStream wr = conn.getOutputStream()) {
            wr.write(request.getBytes(StandardCharsets.UTF_8));
        }

        if (conn.getResponseCode() >= 200 && conn.getResponseCode() < 300) {
            JSONObject response = new JSONObject(Tools.read(conn.getInputStream()));
            conn.disconnect();
            Log.i(TAG, "Token refresh successful");
            return response;
        } else if (conn.getResponseCode() == 403) {
            throw new RuntimeException("Refresh token expired, please login again");
        } else {
            throw new RuntimeException("Token refresh failed: " + conn.getResponseMessage());
        }
    }

    /**
     * Validate token with Ely.by server
     */
    public static boolean validateToken(String accessToken) throws IOException, JSONException, ProtocolException {
        URL url = new URL(ELY_BY_VALIDATE_URL);

        JSONObject data = new JSONObject();
        data.put("accessToken", accessToken);
        data.put("clientToken", "Copper-Android");

        String request = data.toString();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        setCommonProperties(conn, request);
        conn.connect();

        try (OutputStream wr = conn.getOutputStream()) {
            wr.write(request.getBytes(StandardCharsets.UTF_8));
        }

        boolean valid = conn.getResponseCode() >= 200 && conn.getResponseCode() < 300;
        conn.disconnect();
        return valid;
    }

    /**
     * Set common properties for the connection
     */
    private static void setCommonProperties(HttpURLConnection conn, String data) throws ProtocolException {
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestProperty("charset", "utf-8");
        conn.setRequestProperty("Content-Length", Integer.toString(data.getBytes(StandardCharsets.UTF_8).length));
        conn.setRequestMethod("POST");
        conn.setUseCaches(false);
        conn.setDoInput(true);
        conn.setDoOutput(true);
    }

    /**
     * Wrapper to ease notifying the listener
     */
    private void notifyProgress(@Nullable ProgressListener listener, int step) {
        if (listener != null) {
            Tools.runOnUiThread(() -> listener.onLoginProgress(step));
        }
        ProgressLayout.setProgress(ProgressLayout.AUTHENTICATE_MICROSOFT, step * 33);
    }
}
