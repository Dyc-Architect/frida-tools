
Java.perform(function () {
    var secretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    secretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (a, b) {
        showStacks();
        var result = this.$init(a, b);
        console.log("======================================");
        console.log("算法名：" + b + "|str密钥:" + bytesToString(a));
        console.log("算法名：" + b + "|Hex密钥:" + bytesToHex(a));
        return result;
    }

    var DESKeySpec = Java.use('javax.crypto.spec.DESKeySpec');
    DESKeySpec.$init.overload('[B').implementation = function (a) {
        showStacks();
        var result = this.$init(a);
        console.log("======================================");
        var bytes_key_des = this.getKey();
        console.log("des密钥  |str " + bytesToString(bytes_key_des));
        console.log("des密钥  |hex " + bytesToHex(bytes_key_des));
        return result;
    }

    DESKeySpec.$init.overload('[B', 'int').implementation = function (a, b) {
        showStacks();
        var result = this.$init(a, b);
        console.log("======================================");
        var bytes_key_des = this.getKey();
        console.log("des密钥  |str " + bytesToString(bytes_key_des));
        console.log("des密钥  |hex " + bytesToHex(bytes_key_des));
        return result;
    }

    var mac = Java.use('javax.crypto.Mac');
    mac.getInstance.overload('java.lang.String').implementation = function (a) {
        showStacks();
        var result = this.getInstance(a);
        console.log("======================================");
        console.log("算法名：" + a);
        return result;
    }
    mac.update.overload('[B').implementation = function (a) {
        //showStacks();
        this.update(a);
        console.log("======================================");
        console.log("update:" + bytesToString(a))
    }
    mac.update.overload('[B', 'int', 'int').implementation = function (a, b, c) {
        //showStacks();
        this.update(a, b, c)
        console.log("======================================");
        console.log("update:" + bytesToString(a) + "|" + b + "|" + c);
    }
    mac.doFinal.overload().implementation = function () {
        //showStacks();
        var result = this.doFinal();
        console.log("======================================");
        console.log("doFinal结果: |str  :"     + bytesToString(result));
        console.log("doFinal结果: |hex  :"     + bytesToHex(result));
        console.log("doFinal结果: |base64  :"  + bytesToBase64(result));
        return result;
    }
    mac.doFinal.overload('[B').implementation = function (a) {
        //showStacks();
        var result = this.doFinal(a);
        console.log("======================================");
        console.log("doFinal参数: |str  :"     + bytesToString(a));
        console.log("doFinal参数: |hex  :"     + bytesToHex(a));
        console.log("doFinal结果: |str  :"     + bytesToString(result));
        console.log("doFinal结果: |hex  :"     + bytesToHex(result));
        console.log("doFinal结果: |base64  :"  + bytesToBase64(result));
        return result;
    }

    var md = Java.use('java.security.MessageDigest');
    md.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (a, b) {
        //showStacks();
        console.log("======================================");
        console.log("算法名：" + a);
        return this.getInstance(a, b);
    }
    md.getInstance.overload('java.lang.String').implementation = function (a) {
        //showStacks();
        console.log("======================================");
        console.log("算法名：" + a);
        return this.getInstance(a);
    }
    md.update.overload('[B').implementation = function (a) {
        //showStacks();
        console.log("======================================");
        console.log("update:" + bytesToString(a))
        return this.update(a);
    }
    md.update.overload('[B', 'int', 'int').implementation = function (a, b, c) {
        //showStacks();
        console.log("======================================");
        console.log("update:" + bytesToString(a) + "|" + b + "|" + c);
        return this.update(a, b, c);
    }
    md.digest.overload().implementation = function () {
        //showStacks();
        console.log("======================================");
        var result = this.digest();
        console.log("digest结果 |hex:" + bytesToHex(result));
        console.log("digest结果 |base64:" + bytesToBase64(result));
        return result;
    }
    md.digest.overload('[B').implementation = function (a) {
        //showStacks();
        console.log("======================================");
        console.log("digest参数 |str:" + bytesToString(a));
        console.log("digest参数 |hex:" + bytesToHex(a));
        var result = this.digest(a);
        console.log("digest结果: |hex" + bytesToHex(result));
        console.log("digest结果: |base64" + bytesToBase64(result));
        return result;
    }

    var ivParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
    ivParameterSpec.$init.overload('[B').implementation = function (a) {
        //showStacks();
        var result = this.$init(a);
        console.log("======================================");
        console.log("iv向量: |str:" + bytesToString(a));
        console.log("iv向量: |hex:" + bytesToHex(a));
        return result;
    }

    var cipher = Java.use('javax.crypto.Cipher');
    cipher.getInstance.overload('java.lang.String').implementation = function (a) {
        //showStacks();
        var result = this.getInstance(a);
        console.log("======================================");
        console.log("模式填充:" + a);
        return result;
    }
    cipher.init.overload('int', 'java.security.Key').implementation = function (a, b) {
        //showStacks();
        var result = this.init(a, b);
        console.log("======================================");
        if (N_ENCRYPT_MODE == a)
        {
            console.log("init  | 加密模式");
        }
        else if(N_DECRYPT_MODE == a)
        {
            console.log("init  | 解密模式");
        }

        var bytes_key = b.getEncoded();
        console.log("init key:" + "|str密钥:" + bytesToString(bytes_key));
        console.log("init key:" + "|Hex密钥:" + bytesToHex(bytes_key));
        return result;
    }
    cipher.init.overload('int', 'java.security.cert.Certificate').implementation = function (a, b) {
        //showStacks();
        var result = this.init(a, b);
        console.log("======================================");

        if (N_ENCRYPT_MODE == a)
        {
            console.log("init  | 加密模式");
        }
        else if(N_DECRYPT_MODE == a)
        {
            console.log("init  | 解密模式");
        }

        return result;
    }
    cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (a, b, c) {
        //showStacks();
        var result = this.init(a, b, c);
        console.log("======================================");

        if (N_ENCRYPT_MODE == a)
        {
            console.log("init  | 加密模式");
        }
        else if(N_DECRYPT_MODE == a)
        {
            console.log("init  | 解密模式");
        }

        var bytes_key = b.getEncoded();
        console.log("init key:" + "|str密钥:" + bytesToString(bytes_key));
        console.log("init key:" + "|Hex密钥:" + bytesToHex(bytes_key));

        return result;
    }
    cipher.init.overload('int', 'java.security.cert.Certificate', 'java.security.SecureRandom').implementation = function (a, b, c) {
        //showStacks();
        var result = this.init(a, b, c);
        if (N_ENCRYPT_MODE == a)
        {
            console.log("init  | 加密模式");
        }
        else if(N_DECRYPT_MODE == a)
        {
            console.log("init  | 解密模式");
        }
        return result;
    }
    cipher.init.overload('int', 'java.security.Key', 'java.security.SecureRandom').implementation = function (a, b, c) {
        //showStacks();
        var result = this.init(a, b, c);
        if (N_ENCRYPT_MODE == a)
        {
            console.log("init  | 加密模式");
        }
        else if(N_DECRYPT_MODE == a)
        {
            console.log("init  | 解密模式");
        }

         var bytes_key = b.getEncoded();
        console.log("init key:" + "|str密钥:" + bytesToString(bytes_key));
        console.log("init key:" + "|Hex密钥:" + bytesToHex(bytes_key));
        return result;
    }
    cipher.init.overload('int', 'java.security.Key', 'java.security.AlgorithmParameters').implementation = function (a, b, c) {
        //showStacks();
        var result = this.init(a, b, c);
        if (N_ENCRYPT_MODE == a)
        {
            console.log("init  | 加密模式");
        }
        else if(N_DECRYPT_MODE == a)
        {
            console.log("init  | 解密模式");
        }

        var bytes_key = b.getEncoded();
        console.log("init key:" + "|str密钥:" + bytesToString(bytes_key));
        console.log("init key:" + "|Hex密钥:" + bytesToHex(bytes_key));
        return result;
    }
    cipher.init.overload('int', 'java.security.Key', 'java.security.AlgorithmParameters', 'java.security.SecureRandom').implementation = function (a, b, c, d) {
        //showStacks();
        var result = this.init(a, b, c, d);
        if (N_ENCRYPT_MODE == a)
        {
            console.log("init  | 加密模式");
        }
        else if(N_DECRYPT_MODE == a)
        {
            console.log("init  | 解密模式");
        }

        var bytes_key = b.getEncoded();
        console.log("init key:" + "|str密钥:" + bytesToString(bytes_key));
        console.log("init key:" + "|Hex密钥:" + bytesToHex(bytes_key));
        return result;
    }
    cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec', 'java.security.SecureRandom').implementation = function (a, b, c, d) {
        //showStacks();
        var result = this.init(a, b, c, d);
        if (N_ENCRYPT_MODE == a)
        {
            console.log("init  | 加密模式");
        }
        else if(N_DECRYPT_MODE == a)
        {
            console.log("init  | 解密模式");
        }

         var bytes_key = b.getEncoded();
        console.log("init key:" + "|str密钥:" + bytesToString(bytes_key));
        console.log("init key:" + "|Hex密钥:" + bytesToHex(bytes_key));
        return result;
    }

    cipher.update.overload('[B').implementation = function (a) {
        //showStacks();
        var result = this.update(a);
        console.log("======================================");
        console.log("update:" + bytesToString(a));
        return result;
    }
    cipher.update.overload('[B', 'int', 'int').implementation = function (a, b, c) {
        //showStacks();
        var result = this.update(a, b, c);
        console.log("======================================");
        console.log("update:" + bytesToString(a) + "|" + b + "|" + c);
        return result;
    }
    cipher.doFinal.overload().implementation = function () {
        //showStacks();
        var result = this.doFinal();
        console.log("======================================");
        console.log("doFinal结果: |str  :"     + bytesToString(result));
        console.log("doFinal结果: |hex  :"     + bytesToHex(result));
        console.log("doFinal结果: |base64  :"  + bytesToBase64(result));
        return result;
    }
    cipher.doFinal.overload('[B').implementation = function (a) {
        //showStacks();
        var result = this.doFinal(a);
        console.log("======================================");
        console.log("doFinal参数: |str  :"     + bytesToString(a));
        console.log("doFinal参数: |hex  :"     + bytesToHex(a));
        console.log("doFinal结果: |str  :"     + bytesToString(result));
        console.log("doFinal结果: |hex  :"     + bytesToHex(result));
        console.log("doFinal结果: |base64  :"  + bytesToBase64(result));
        return result;
    }

    var x509EncodedKeySpec = Java.use('java.security.spec.X509EncodedKeySpec');
    x509EncodedKeySpec.$init.overload('[B').implementation = function (a) {
        //showStacks();
        var result = this.$init(a);
        console.log("======================================");
        console.log("RSA密钥:" + bytesToBase64(a));
        return result;
    }

    var rSAPublicKeySpec = Java.use('java.security.spec.RSAPublicKeySpec');
    rSAPublicKeySpec.$init.overload('java.math.BigInteger', 'java.math.BigInteger').implementation = function (a, b) {
        //showStacks();
        var result = this.$init(a, b);
        console.log("======================================");
        //console.log("RSA密钥:" + bytesToBase64(a));
        console.log("RSA密钥N:" + a.toString(16));
        console.log("RSA密钥E:" + b.toString(16));
        return result;
    }

    var KeyPairGenerator = Java.use('java.security.KeyPairGenerator');
    KeyPairGenerator.generateKeyPair.implementation = function ()
    {
        //showStacks();
        var result = this.generateKeyPair();
        console.log("======================================");

        var str_private = result.getPrivate().getEncoded();
        var str_public = result.getPublic().getEncoded();
        console.log("公钥  |hex" + bytesToHex(str_public));
        console.log("私钥  |hex" + bytesToHex(str_private));

        return result;
    }

    KeyPairGenerator.genKeyPair.implementation = function ()
    {
        //showStacks();
        var result = this.genKeyPair();
        console.log("======================================");

        var str_private = result.getPrivate().getEncoded();
        var str_public = result.getPublic().getEncoded();
        console.log("公钥  |hex" + bytesToHex(str_public));
        console.log("私钥  |hex" + bytesToHex(str_private));

        return result;
    }
});