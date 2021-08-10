package com.emeraldsanto.encryptedstorage;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;
import android.provider.Settings;
import android.app.KeyguardManager;
import android.os.Build;
import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;


public class RNEncryptedStorageModule extends ReactContextBaseJavaModule {

    private static final String NATIVE_MODULE_NAME = "RNEncryptedStorage";
    private static final String SHARED_PREFERENCES_FILENAME = "RN_ENCRYPTED_STORAGE_SHARED_PREF";

    private SharedPreferences sharedPreferences;
    private boolean isDeviceProtectedFlag;

    public RNEncryptedStorageModule(ReactApplicationContext context) {
        super(context);

        try {
            MasterKey key = new MasterKey.Builder(context)
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .build();

            this.sharedPreferences = EncryptedSharedPreferences.create(
                context,
                RNEncryptedStorageModule.SHARED_PREFERENCES_FILENAME,
                key,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            );
        }
        catch (Exception ex) {
            Log.e(NATIVE_MODULE_NAME, "Failed to create encrypted shared preferences! Failing back to standard SharedPreferences", ex);
            this.sharedPreferences = context.getSharedPreferences(RNEncryptedStorageModule.SHARED_PREFERENCES_FILENAME, Context.MODE_PRIVATE);
        }

        // Detect device protection
        KeyguardManager keyguardManager = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE); //api 23+

        // On devices with API level >= 23 (from around 2017) there is a single method
        // that does correct check for whether device is secured by a passcode or unlock pattern.
        // Older OSes have separate methods for pattern and for pincode/passcode, and, unfortunately,
        // isKeyguardSecure returns `true` in case there's a PIN on simcard, which is irrelevant to us.
        // If we are to be extra paranoid, we need to either return `false` for all older devices or
        // only return true if the pattern is set, therefore forcing user to use in-wallet password.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            this.isDeviceProtectedFlag = keyguardManager.isDeviceSecure();
        } else {
            boolean patternSet = false;
            ContentResolver cr = context.getContentResolver();
            try {
                int lockPatternEnable = Settings.Secure.getInt(cr, Settings.Secure.LOCK_PATTERN_ENABLED);
                patternSet = (lockPatternEnable == 1);
            } catch (Settings.SettingNotFoundException e) {
            }
            this.isDeviceProtectedFlag =  keyguardManager.isKeyguardSecure() || patternSet;
        }
    }

    @Override
    public String getName() {
        return RNEncryptedStorageModule.NATIVE_MODULE_NAME;
    }

    @ReactMethod
    public void isDeviceProtected(Promise promise) {
        promise.resolve(Boolean.valueOf(this.isDeviceProtectedFlag));
    }

    @ReactMethod
    public void setItem(String key, String value, Promise promise) {
        if (this.sharedPreferences == null) {
            promise.reject(new NullPointerException("Could not initialize SharedPreferences"));
            return;
        }

        SharedPreferences.Editor editor = this.sharedPreferences.edit();
        editor.putString(key, value);
        boolean saved = editor.commit();

        if (saved) {
            promise.resolve(value);
        }

        else {
            promise.reject(new Exception(String.format("An error occurred while saving %s", key)));
        }
    }

    @ReactMethod
    public void getItem(String key, Promise promise) {
        if (this.sharedPreferences == null) {
            promise.reject(new NullPointerException("Could not initialize SharedPreferences"));
            return;
        }

        String value = this.sharedPreferences.getString(key, null);

        promise.resolve(value);
    }

    @ReactMethod
    public void removeItem(String key, Promise promise) {
        if (this.sharedPreferences == null) {
            promise.reject(new NullPointerException("Could not initialize SharedPreferences"));
            return;
        }

        SharedPreferences.Editor editor = this.sharedPreferences.edit();
        editor.remove(key);
        boolean saved = editor.commit();

        if (saved) {
            promise.resolve(key);
        }

        else {
            promise.reject(new Exception(String.format("An error occured while removing %s", key)));
        }
    }

    @ReactMethod
    public void clear(Promise promise) {
        if (this.sharedPreferences == null) {
            promise.reject(new NullPointerException("Could not initialize SharedPreferences"));
            return;
        }

        SharedPreferences.Editor editor = this.sharedPreferences.edit();
        editor.clear();
        boolean saved = editor.commit();

        if (saved) {
            promise.resolve(null);
        }

        else {
            promise.reject(new Exception("An error occured while clearing SharedPreferences"));
        }
    }
}
