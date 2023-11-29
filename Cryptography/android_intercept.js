if (Java.available) {
    Java.perform(function () {
        // Example: Hook into javax.crypto.Cipher.getInstance
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.getInstance.overload('java.lang.String').implementation = function (algorithm) {
            console.log('Cipher.getInstance called with algorithm: ' + algorithm);
            var instance = this.getInstance(algorithm);
            return instance;
        };

        // Hook into java.security.MessageDigest.getInstance
        var MessageDigest = Java.use('java.security.MessageDigest');
        MessageDigest.getInstance.overload('java.lang.String').implementation = function (algorithm) {
            console.log('MessageDigest.getInstance called with algorithm: ' + algorithm);
            var instance = this.getInstance(algorithm);
            return instance;
        };

        // Hook into javax.crypto.Mac.getInstance
        var Mac = Java.use('javax.crypto.Mac');
        Mac.getInstance.overload('java.lang.String').implementation = function (algorithm) {
            console.log('Mac.getInstance called with algorithm: ' + algorithm);
            var instance = this.getInstance(algorithm);
            return instance;
        };

        var AccountManager = Java.use('android.accounts.AccountManager');
        AccountManager.getAccounts.overload().implementation = function () {
        var accounts = this.getAccounts();
        console.log('getAccounts called. Accounts: ' + accounts);
        return accounts;
        };

        var SharedPreferences = Java.use('android.content.SharedPreferences');
        SharedPreferences.getString.overload('java.lang.String', 'java.lang.String').implementation = function (key, defaultValue) {
            var value = this.getString(key, defaultValue);
            console.log('SharedPreferences.getString called. Key: ' + key + ', Value: ' + value);
            return value;
        };

        var KeyStore = Java.use('android.security.keystore.KeyStore');
        KeyStore.getInstance.overload('java.lang.String').implementation = function (provider) {
            console.log('KeyStore.getInstance called. Provider: ' + provider);
            return this.getInstance(provider);
        };

        var FingerprintManager = Java.use('android.hardware.fingerprint.FingerprintManager');
        FingerprintManager.authenticate.overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler').implementation = function (crypto, cancel, flags, callback, handler) {
            console.log('FingerprintManager.authenticate called.');
            return this.authenticate(crypto, cancel, flags, callback, handler);
        };
    });
} else {
    console.log('Java is not available');
}

rpc.exports = {
    is_insecure_algorithm: function (algorithm) {
        var insecure_algorithms = ['DES', 'MD5', 'SHA-1', 'RC4', 'ECB'];
        for (var i = 0; i < insecure_algorithms.length; i++) {
            var pattern = new RegExp('\\b' + insecure_algorithms[i] + '\\b', 'i');
            if (pattern.test(algorithm)) {
                return true;
            }
        }
        return false;
    }
};

