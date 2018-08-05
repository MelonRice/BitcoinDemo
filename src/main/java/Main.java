import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import io.github.novacrypto.base58.Base58;
import io.github.novacrypto.bip32.ExtendedPrivateKey;
import io.github.novacrypto.bip32.networks.Bitcoin;
import io.github.novacrypto.bip44.AddressIndex;
import io.github.novacrypto.bip44.BIP44;
import io.github.novacrypto.hashing.Sha256;

import static io.github.novacrypto.toruntime.CheckedExceptionToRuntime.toRuntime;

import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Utils;


public class Main {

    private static final String[] dict =
            {"0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111", "1000",
                    "1001", "1010", "1011", "1100", "1101", "1110", "1111"};

    private static String[] wordlist = new String[2048];
    private static GenerateKeyStore ks = new GenerateKeyStore();

    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException {
        String entropy = createEntropy();
        String mnemonic = generateMnemonic(entropy);
        System.out.println(mnemonic);
        List<String> params = generateBTCKeyPairs(mnemonic);
        String password = "password";
        genKeyStore(params.get(0), params.get(2), password);
    }

    public static String createEntropy() {
        UUID uuid = UUID.randomUUID();
        String[] digits = uuid.toString().split("\\-");
        StringBuilder randomDigits = new StringBuilder();
        for (String digit : digits) {
            randomDigits.append(digit);
        }
        return randomDigits.toString();
    }

    public static String generateMnemonic(String entropy) {
        System.out.println(entropy);

        //generate sha-256 from entropy
        MessageDigest messageDigest;
        String encodeStr = "";
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] hash = messageDigest.digest(entropy.getBytes("UTF-8"));
            encodeStr = String.valueOf(Hex.encodeHex(hash));
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        System.out.println(encodeStr);
        char firstSHA = encodeStr.charAt(0);
        String new_entropy = entropy + firstSHA;
        StringBuilder bin_entropy = new StringBuilder();
        for (int i = 0; i < new_entropy.length(); i++) {
            bin_entropy.append(dict[Integer.parseInt(new_entropy.substring(i, i + 1), 16)]);
        }
        System.out.println(bin_entropy);
        String[] segments = new String[12];
        //hardcode
        for (int i = 0; i <= 11; i++) {
            segments[i] = bin_entropy.substring(i * 11, (i + 1) * 11);
        }

        //请修改文件的绝对路径
        String path = "src/main/java/english";
        readTextFile(path);
        StringBuilder mnemonic = new StringBuilder();

        //generate mnemonic
        mnemonic.append(wordlist[Integer.valueOf(segments[0], 2)]);
        for (int j = 1; j < segments.length; j++) {
            mnemonic.append(" ").append(wordlist[Integer.valueOf(segments[j], 2)]);
        }
        return mnemonic.toString();
    }


    public static void readTextFile(String filePath) {
        try {
            String encoding = "utf-8";
            File file = new File(filePath);
            if (file.isFile() && file.exists()) { //判断文件是否存在
                InputStreamReader read = new InputStreamReader(
                        new FileInputStream(file), encoding);//考虑到编码格式
                BufferedReader bufferedReader = new BufferedReader(read);
                String lineTxt;
                int index = 0;
                while ((lineTxt = bufferedReader.readLine()) != null) {
                    wordlist[index++] = lineTxt;
                }
                read.close();
            } else {
                System.out.println("找不到指定的文件");
            }
        } catch (Exception e) {
            System.out.println("读取文件内容出错");
            e.printStackTrace();
        }
    }

    /**
     * 生成以太坊私钥、公钥、地址
     * @param mnemonic
     * @return
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    private static List<String> generateKeyPairs(String mnemonic) throws InvalidKeySpecException, NoSuchAlgorithmException {

        // 1. we just need eth wallet for now
        AddressIndex addressIndex = BIP44.m().purpose44().coinType(60).account(0).external().address(0);
        // 2. calculate seed from mnemonics , then get master/root key ; Note that the bip39 passphrase we set "" for common
        String seed;
        String salt = "mnemonic";
        seed = getSeed(mnemonic, salt);
        System.out.println(seed);


        ExtendedPrivateKey rootKey = ExtendedPrivateKey.fromSeed(fromHex(seed), Bitcoin.MAIN_NET);
        // 3. get child private key deriving from master/root key
        ExtendedPrivateKey childPrivateKey = rootKey.derive(addressIndex, AddressIndex.DERIVATION);

        // 4. get key pair
        byte[] privateKeyBytes = childPrivateKey.getKey(); //child private key
        ECKeyPair keyPair = ECKeyPair.create(privateKeyBytes);

        // we 've gotten what we need
        String privateKey = childPrivateKey.getPrivateKey();
        String publicKey = childPrivateKey.neuter().getPublicKey();
        String address = Keys.getAddress(keyPair);
        List<String> returnList = new ArrayList<>();

        System.out.println("privateKey:" + privateKey);
        System.out.println("publicKey:" + publicKey);
        System.out.println("address:" + address);
        returnList.add(privateKey);
        returnList.add(publicKey);
        returnList.add(address);
        return returnList;
    }

    /**
     * 生成比特币私钥、公钥、地址
     * @param mnemonic
     * @return
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    private static List<String> generateBTCKeyPairs(String mnemonic) throws InvalidKeySpecException, NoSuchAlgorithmException {

        AddressIndex addressIndex = BIP44.m().purpose44().coinType(0).account(0).external().address(0);
        String seed;
        String salt = "mnemonic";
        seed = getSeed(mnemonic, salt);
        System.out.println(seed);


        /*
         * 生成比特币私钥
         */

        ExtendedPrivateKey rootKey = ExtendedPrivateKey.fromSeed(fromHex(seed), Bitcoin.MAIN_NET);
        ExtendedPrivateKey childPrivateKey = rootKey.derive(addressIndex, AddressIndex.DERIVATION);
        // 获取比特币私钥
        String privateKey = childPrivateKey.getPrivateKey();
        // 加80前缀和01后缀
        String rk = "80" + privateKey + "01";
        // 生成校验和
        byte[] checksum = Sha256.sha256(hexStringToByteArray(rk));
        checksum = Sha256.sha256(checksum);
        // 取校验和前4位（32bits）
        String end = String.valueOf(Hex.encodeHex(checksum)).substring(0, 8);
        rk = rk + end;
        // 进行base58编码生成最终的私钥
        String privateK = Base58.base58Encode(hexStringToByteArray(rk));

        /*
          生成比特币地址
         */

        // 获取比特币公钥
        String publicKey = childPrivateKey.neuter().getPublicKey();

        // 对公钥进行一次sha256
        byte[] pk256 = hexStringToByteArray(publicKey);
        pk256 = Sha256.sha256(pk256);
        // 进行ripe160加密（20位）
        RIPEMD160Digest digest = new RIPEMD160Digest();
        digest.update(pk256, 0, pk256.length);
        byte[] ripemd160Bytes = new byte[digest.getDigestSize()];
        digest.doFinal(ripemd160Bytes, 0);
        // 加00前缀（比特币主网）变成21位
        byte[] extendedRipemd160Bytes = hexStringToByteArray("00" + String.valueOf(Hex.encodeHex(ripemd160Bytes)));
        // 计算校验和
        checksum = Sha256.sha256(extendedRipemd160Bytes);
        checksum = Sha256.sha256(checksum);
        // 加校验和前4位，变成25位
        String pk = String.valueOf(Hex.encodeHex(extendedRipemd160Bytes)) + String.valueOf(Hex.encodeHex(checksum)).substring(0, 8);
        // base58加密生成最终的比特币地址
        String address = Base58.base58Encode(hexStringToByteArray(pk));


        System.out.println("privateKey:" + privateK);
        System.out.println("publicKey:" + publicKey);
        System.out.println("address:" + address);
        List<String> returnList = new ArrayList<>();
        returnList.add(privateKey);
        returnList.add(publicKey);
        returnList.add(address);
        //比特币隔离见证地址
        generateSegwitAddress(address);
        return returnList;
    }

    /*
        比特币隔离见证地址
     */
    private static void generateSegwitAddress(String address){
        byte[] decoded = Utils.parseAsHexOrBase58(address);
        // We should throw off header byte that is 0 for Bitcoin (Main)
        byte[] pureBytes = new byte[20];
        System.arraycopy(decoded, 1, pureBytes, 0, 20);
        // Than we should prepend the following bytes:
        byte[] scriptSig = new byte[pureBytes.length + 2];
        scriptSig[0] = 0x00;
        scriptSig[1] = 0x14;
        System.arraycopy(pureBytes, 0, scriptSig, 2, pureBytes.length);
        byte[] addressBytes = org.bitcoinj.core.Utils.sha256hash160(scriptSig);
        // Here are the address bytes
        byte[] readyForAddress = new byte[addressBytes.length + 1 + 4];
        // prepending p2sh header:
        readyForAddress[0] = (byte) 5;
        System.arraycopy(addressBytes, 0, readyForAddress, 1, addressBytes.length);
        // But we should also append check sum:
        byte[] checkSum = Sha256Hash.hashTwice(readyForAddress, 0, addressBytes.length + 1);
        System.arraycopy(checkSum, 0, readyForAddress, addressBytes.length + 1, 4);
        // To get the final address:
        String segwitAddress = Base58.base58Encode(readyForAddress);
        System.out.println("segwit address:" + segwitAddress);
    }


    public static String getSeed(String mnemonic, String salt) throws NoSuchAlgorithmException,
            InvalidKeySpecException {

        char[] chars = Normalizer.normalize(mnemonic, Normalizer.Form.NFKD).toCharArray();
        byte[] salt_ = getUtf8Bytes(salt);
        KeySpec spec = new PBEKeySpec(chars, salt_, 2048, 512);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        return String.valueOf(Hex.encodeHex(f.generateSecret(spec).getEncoded()));
    }

    private static byte[] fromHex(String hex) {
        byte[] binary = new byte[hex.length() / 2];
        for (int i = 0; i < binary.length; i++) {
            binary[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return binary;

    }

    private static byte[] getUtf8Bytes(final String string) {
        return toRuntime(() -> string.getBytes("UTF-8"));
    }

    private static void genKeyStore(String ksContent, String ksName, String ksPassword){
        ks.genkey(ksName, ksPassword);
        try {
            Thread.sleep(1000); //1000 毫秒，也就是1秒.
        } catch(InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
        ks.protectContent(ksContent, ksPassword);
        ks.getContent(ksPassword);
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}


