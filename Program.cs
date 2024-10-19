using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Net.Http;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Diagnostics;
using Newtonsoft.Json;

namespace MSYK_ANSWER_2024
{
    class Program
    {
        // 配置
        private static readonly string ProfileCachePath = "ProfileCache.txt";
        private static readonly string EncryptionKey = "Try2CATCHmeHAhaHa"; // 请使用一个安全的密钥
        private static readonly string MsykSignPubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAj7YWxpOwulFyf+zQU77Y2cd9chZUMfiwokgUaigyeD8ac5E8LQpVHWzkm+1CuzH0GxTCWvAUVHWfefOEe4AThk4AbFBNCXqB+MqofroED6Uec1jrLGNcql9IWX3CN2J6mqJQ8QLB/xPg/7FUTmd8KtGPrtOrKKP64BM5cqaB1xCc4xmQTuWvtK9fRei6LVTHZyH0Ui7nP/TSF3PJV3ywMlkkQxKi8JBkz1fx1ZO5TVLYRKxzMQdeD6whq+kOsSXhlLIiC/Y8skdBJmsBWDMfQXxtMr5CyFbVMrG+lip/V5n22EdigHcLOmFW9nnB+sgiifLHeXx951lcTmaGy4uChQIDAQAB";
        private static readonly string MsykKey = "DxlE8wwbZt8Y2ULQfgGywAgZfJl82G9S";
        private static readonly HttpClient httpClient = new HttpClient();
        private static readonly Dictionary<string, string> Headers = new Dictionary<string, string>
        {
            { "User-Agent", "okhttp/3.12.1" }
        };

        // 全局变量
        private static string SerialNumbers = "";
        private static string Answers = "";
        private static string Sign = "";
        private static string UnitId = "";
        private static string Id = "";

        static async Task Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteLine("初始化中...");

            await GetAccountInfoAsync();

            // 获取作业列表
            var homeworkList = await GetHomeworkListAsync();
            foreach (var item in homeworkList)
            {
                var timePrint = UnixTimeToDateTime(item.EndTime).ToString("yyyy-MM-dd HH:mm:ss");
                Console.WriteLine($"{ConsoleColor.Yellow}{item.Id} 作业类型:{item.HomeworkType} {item.HomeworkName} 截止时间:{timePrint}");
            }

            // 主循环
            while (true)
            {
                await MainMenuAsync();
            }
        }

        #region 加密解密方法

        // AES 加密
        private static string EncryptString(string plainText, string key)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = SHA256Hash(key);
                aes.GenerateIV();
                using (var encryptor = aes.CreateEncryptor())
                using (var ms = new MemoryStream())
                {
                    ms.Write(aes.IV, 0, aes.IV.Length);
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    using (var sw = new StreamWriter(cs))
                    {
                        sw.Write(plainText);
                    }
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }

        // AES 解密
        private static string DecryptString(string cipherText, string key)
        {
            try
            {
                byte[] fullCipher = Convert.FromBase64String(cipherText);
                using (Aes aes = Aes.Create())
                {
                    aes.Key = SHA256Hash(key);
                    byte[] iv = new byte[aes.BlockSize / 8];
                    Array.Copy(fullCipher, 0, iv, 0, iv.Length);
                    aes.IV = iv;
                    int cipherStart = iv.Length;
                    int cipherLength = fullCipher.Length - cipherStart;
                    using (var decryptor = aes.CreateDecryptor())
                    using (var ms = new MemoryStream(fullCipher, cipherStart, cipherLength))
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (var sr = new StreamReader(cs))
                    {
                        return sr.ReadToEnd();
                    }
                }
            }
            catch
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("警告: ProfileCache 解密失败!");
                Console.ResetColor();
                return null;
            }
        }

        // SHA256 Hash
        private static byte[] SHA256Hash(string input)
        {
            using (var sha = SHA256.Create())
            {
                return sha.ComputeHash(Encoding.UTF8.GetBytes(input));
            }
        }

        #endregion

        #region RSA 解密方法

        private static string PublicKeyDecrypt(string publicKey, string content)
        {
            try
            {
                byte[] data = Convert.FromBase64String(content);
                using (var rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out _);
                    byte[] decryptedData = rsa.Decrypt(data, false);
                    return Encoding.UTF8.GetString(decryptedData).Substring(1);
                }
            }
            catch
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("警告: sign 解密失败!");
                Console.ResetColor();
                return null;
            }
        }

        #endregion

        #region 工具方法

        // 当前时间的毫秒级时间戳
        private static long GetCurrentTimeMillis()
        {
            return DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        }

        // 十位或十三位时间戳转DateTime
        private static DateTime UnixTimeToDateTime(long unixTime)
        {
            if (unixTime.ToString().Length == 13)
                return DateTimeOffset.FromUnixTimeMilliseconds(unixTime).LocalDateTime;
            else
                return DateTimeOffset.FromUnixTimeSeconds(unixTime).LocalDateTime;
        }

        // MD5 哈希
        private static string StringToMD5(string input)
        {
            using (var md5 = MD5.Create())
            {
                var bytes = md5.ComputeHash(Encoding.UTF8.GetBytes(input));
                return BitConverter.ToString(bytes).Replace("-", "").ToLower();
            }
        }

        // 打开浏览器
        private static void OpenUrl(string url)
        {
            try
            {
                Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true });
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"无法打开浏览器: {ex.Message}");
                Console.ResetColor();
            }
        }

        #endregion

        #region ProfileCache 处理

        // 获取账号信息
        private static async Task GetAccountInfoAsync()
        {
            string returnInform = "";
            try
            {
                if (File.Exists(ProfileCachePath))
                {
                    var encryptedContent = await File.ReadAllTextAsync(ProfileCachePath);
                    returnInform = DecryptString(encryptedContent, EncryptionKey);
                    if (!string.IsNullOrEmpty(returnInform))
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("检测到 ProfileCache，尝试缓存登录中。（如失败自动执行登录流程）");
                        Console.ResetColor();
                        SetAccountInform(returnInform);
                        return;
                    }
                }
                throw new Exception("ProfileCache 未找到或解密失败。");
            }
            catch
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("未检测到 ProfileCache，执行登录流程。");
                Console.ResetColor();
                await LoginAsync();
            }
        }

        // 设置账号信息
        private static void SetAccountInform(string result)
        {
            var json = JsonConvert.DeserializeObject<dynamic>(result);
            if (json.code == "10000")
            {
                // 保存登录信息
                string realName = json.InfoMap.realName;
                SaveJson(result, $"{realName}.json");
                File.WriteAllText(ProfileCachePath, EncryptString(result, EncryptionKey));
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("ProfileCache 登录缓存已更新。(下一次优先自动读取)");
                Console.ResetColor();

                UnitId = json.InfoMap.unitId;
                Id = json.InfoMap.id;

                string signDecrypted = PublicKeyDecrypt(MsykSignPubKey, json.sign.ToString());
                if (signDecrypted != null)
                {
                    var signParts = signDecrypted.Split(':');
                    if (signParts.Length > 1)
                    {
                        Sign = signParts[1] + Id;
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"sign解密成功: {signDecrypted}");
                        Console.ResetColor();
                    }
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine((string)json.message);
                Console.ResetColor();
                Environment.Exit(1);
            }
        }

        // 保存JSON到文件
        private static void SaveJson(string data, string filename)
        {
            try
            {
                File.WriteAllText($"{filename}.json", data);
                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.WriteLine($"保存登录信息成功 {filename}.json");
                Console.ResetColor();
            }
            catch
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("保存登录信息失败");
                Console.ResetColor();
            }
        }

        #endregion

        #region 登录方法

        private static async Task LoginAsync()
        {
            Console.Write("用户名: ");
            string userName = Console.ReadLine();
            Console.Write("密码: ");
            string pwd = ReadPassword();
            Console.Write("mac: ");
            string mac = Console.ReadLine().ToUpper();
            Console.Write("安卓API: ");
            string api = Console.ReadLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write("SN(区分大小写): ");
            Console.ResetColor();
            string sn = Console.ReadLine();

            string genauth = StringToMD5(userName + pwd + "HHOO");
            var dataUp = new Dictionary<string, string>
            {
                { "userName", userName },
                { "auth", genauth },
                { "macAddress", mac },
                { "versionCode", api },
                { "sn", sn }
            };

            string extra = genauth + mac + sn + userName + api;
            string res = await PostAsync("https://padapp.msyk.cn/ws/app/padLogin", dataUp, 1, extra);
            SetAccountInform(res);
        }

        // 读取密码（隐藏输入）
        private static string ReadPassword()
        {
            StringBuilder password = new StringBuilder();
            ConsoleKeyInfo keyInfo;
            do
            {
                keyInfo = Console.ReadKey(intercept: true);
                if (keyInfo.Key == ConsoleKey.Backspace && password.Length > 0)
                {
                    Console.Write("\b \b");
                    password.Length--;
                }
                else if (!char.IsControl(keyInfo.KeyChar))
                {
                    Console.Write("*");
                    password.Append(keyInfo.KeyChar);
                }
            } while (keyInfo.Key != ConsoleKey.Enter);
            Console.WriteLine();
            return password.ToString();
        }

        #endregion

        #region POST 请求

        private static async Task<string> PostAsync(string url, Dictionary<string, string> postData, int type = 1, string extra = "")
        {
            long time = GetCurrentTimeMillis();
            string key = "";

            switch (type)
            {
                case 1:
                    key = StringToMD5(extra + time + Sign + MsykKey);
                    break;
                case 2:
                    key = StringToMD5(extra + Id + UnitId + time + Sign + MsykKey);
                    break;
                case 3:
                    key = StringToMD5(extra + UnitId + Id + time + Sign + MsykKey);
                    break;
                default:
                    break;
            }

            postData.Add("salt", time.ToString());
            postData.Add("sign", Sign);
            postData.Add("key", key);

            try
            {
                var content = new FormUrlEncodedContent(postData);
                foreach (var header in Headers)
                {
                    if (!httpClient.DefaultRequestHeaders.Contains(header.Key))
                        httpClient.DefaultRequestHeaders.Add(header.Key, header.Value);
                }
                var response = await httpClient.PostAsync(url, content);
                return await response.Content.ReadAsStringAsync();
            }
            catch
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"{url} {JsonConvert.SerializeObject(postData)}");
                Console.WriteLine("网络异常 请检查代理设置");
                Console.ResetColor();
                Environment.Exit(1);
                return null;
            }
        }

        #endregion

        #region 获取答案

        private static async Task GetAnswerAsync()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("请输入作业id: ");
            Console.ResetColor();
            string hwidInput = Console.ReadLine();
            if (!int.TryParse(hwidInput, out int hwid))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("无效的作业id。");
                Console.ResetColor();
                return;
            }

            var dataUp = new Dictionary<string, string>
            {
                { "homeworkId", hwid.ToString() },
                { "studentId", Id },
                { "modifyNum", "0" },
                { "unitId", UnitId }
            };

            string res = await PostAsync("https://padapp.msyk.cn/ws/teacher/homeworkCard/getHomeworkCardInfo", dataUp, 2, hwid.ToString() + "0");
            dynamic json = JsonConvert.DeserializeObject(res);

            var materialRelasList = json.materialRelas;
            var analysistList = json.analysistList;
            string hwname = json.homeworkName;
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine(hwname);
            Console.ResetColor();

            var resList = json.homeworkCardList;
            List<string> materialRelasUrls = new List<string>();
            List<string> analysistUrls = new List<string>();
            List<string> materialRelasFiles = new List<string>();
            List<string> analysistFiles = new List<string>();

            // 处理材料文件
            if (materialRelasList.Count == 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("没有材料文件");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.WriteLine("材料文件:");
                Console.ResetColor();
                foreach (var file in materialRelasList)
                {
                    string fileUrl = ProcessUrl(file.resourceUrl.ToString());
                    materialRelasFiles.Add(file.title.ToString());
                    materialRelasUrls.Add(fileUrl);
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"\t{file.title} {fileUrl}");
                    Console.ResetColor();
                }
            }

            // 处理答案文件
            if (analysistList.Count == 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("没有答案文件");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.WriteLine("答案文件:");
                Console.ResetColor();
                foreach (var file in analysistList)
                {
                    string fileUrl = ProcessUrl(file.resourceUrl.ToString());
                    analysistFiles.Add(file.title.ToString());
                    analysistUrls.Add(fileUrl);
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"\t{file.title} {fileUrl}");
                    Console.ResetColor();
                }
            }

            // 处理题目
            List<string> questionList = new List<string>();
            SerialNumbers = "";
            Answers = "";

            foreach (var question in resList)
            {
                string serialNumber = question.serialNumber.ToString();
                string url = $"https://www.msyk.cn/webview/newQuestion/singleDoHomework?studentId={Id}&homeworkResourceId={question.resourceId}&orderNum={question.orderNum}&showAnswer=1&unitId={UnitId}&modifyNum=1";
                string vinkResponse = await httpClient.GetStringAsync(url);
                string answer = ParseVinkResponse(vinkResponse, question.orderNum.ToString(), url);
                questionList.Add(question.resourceId.ToString());

                if (answer != "wtf")
                {
                    answer = AnswerEncode(answer);
                    if (string.IsNullOrEmpty(SerialNumbers))
                    {
                        SerialNumbers += serialNumber;
                        Answers += answer;
                    }
                    else
                    {
                        SerialNumbers += ";" + serialNumber;
                        Answers += ";" + answer;
                    }
                }
            }

            Console.WriteLine(string.Join(", ", questionList));

            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.Write("是否要提交选择答案 y/N: ");
            Console.ResetColor();
            string up = Console.ReadLine();
            if (up.Equals("Y", StringComparison.OrdinalIgnoreCase))
            {
                var dataSubmit = new Dictionary<string, string>
                {
                    { "serialNumbers", SerialNumbers },
                    { "answers", Answers },
                    { "studentId", Id },
                    { "homeworkId", hwid.ToString() },
                    { "unitId", UnitId },
                    { "modifyNum", "0" }
                };
                string resSubmit = await PostAsync("https://padapp.msyk.cn/ws/teacher/homeworkCard/saveCardAnswerObjectives", dataSubmit, 2, Answers + hwid + "0" + SerialNumbers);
                dynamic jsonSubmit = JsonConvert.DeserializeObject(resSubmit);
                if (jsonSubmit.code == "10000")
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("自动提交选择答案成功");
                    Console.ResetColor();
                }
            }

            // 下载文件
            if (analysistList.Count != 0 || materialRelasList.Count != 0)
            {
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.Write("是否要下载文件 y/N: ");
                Console.ResetColor();
                string down = Console.ReadLine();
                if (down.Equals("Y", StringComparison.OrdinalIgnoreCase))
                {
                    foreach (var (url, file) in Zip(materialRelasUrls, materialRelasFiles))
                    {
                        await DownloadFileAsync(url, file);
                    }
                    foreach (var (url, file) in Zip(analysistUrls, analysistFiles))
                    {
                        await DownloadFileAsync(url, file);
                    }
                }
            }

            SerialNumbers = "";
            Answers = "";
        }

        // 解析Vink响应
        private static string ParseVinkResponse(string htmlDoc, string count, string url)
        {
            htmlDoc = htmlDoc.Replace("\n", "");
            int index = htmlDoc.IndexOf("var questions = ");
            int index1 = htmlDoc.IndexOf("var resource");
            if (index != -1 && index1 != -1)
            {
                string dataStr = htmlDoc.Substring(index + 16, index1 - index - 23);
                var data = JsonConvert.DeserializeObject<dynamic>(dataStr);
                if (data[0].answer != null)
                {
                    string answer = string.Join("", data[0].answer.ToObject<List<string>>()).TrimStart('[').TrimEnd(']').Replace("\"", "").Replace(",", " ");
                    if (Regex.IsMatch(answer, @"\d"))
                    {
                        OpenUrl(url);
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"{count} 在浏览器中打开");
                        Console.ResetColor();
                        return "wtf";
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"{count} {answer}");
                        Console.ResetColor();
                        return answer;
                    }
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"{count} 没有检测到答案,有可能是主观题");
                    Console.ResetColor();
                    return "wtf";
                }
            }
            return "wtf";
        }

        // 答案编码
        private static string AnswerEncode(string answer)
        {
            if (answer.Length == 1)
                return answer;

            StringBuilder answerCode = new StringBuilder();
            foreach (char option in "ABCDEFGHIJ")
            {
                answerCode.Append(answer.Contains(option.ToString()) ? "1" : "0");
            }
            return answerCode.ToString();
        }

        #endregion

        #region 下载文件

        private static async Task DownloadFileAsync(string url, string fileName)
        {
            try
            {
                byte[] content = await httpClient.GetByteArrayAsync(url);
                await File.WriteAllBytesAsync(fileName, content);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"下载完成: {fileName}");
                Console.ResetColor();
            }
            catch
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"下载失败: {fileName}");
                Console.ResetColor();
            }
        }

        // Zip两个列表
        private static IEnumerable<(string, string)> Zip(List<string> list1, List<string> list2)
        {
            int count = Math.Min(list1.Count, list2.Count);
            for (int i = 0; i < count; i++)
                yield return (list1[i], list2[i]);
        }

        #endregion

        #region 解析URL

        private static string ProcessUrl(string resourceUrl)
        {
            if (resourceUrl.ToLower().StartsWith("http"))
                return resourceUrl;
            else if (resourceUrl.ToLower().StartsWith("//") || resourceUrl.ToLower().StartsWith("/"))
                return $"https://msyk.wpstatic.cn{resourceUrl}";
            else
                return $"https://msyk.wpstatic.cn/{resourceUrl}";
        }

        #endregion

        #region 主菜单

        private static async Task MainMenuAsync()
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("1. 作业获取答案(默认)\n2. 跑作业id\n3. 切换账号");
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write("请选择要执行的任务: ");
            Console.ResetColor();
            string mission = Console.ReadLine();

            switch (mission)
            {
                case "2":
                    await GetUnreleasedHWIDAsync();
                    break;
                case "3":
                    File.WriteAllText(ProfileCachePath, EncryptString(string.Empty, EncryptionKey));
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("已清空 ProfileCache 登录缓存。");
                    Console.ResetColor();
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write("请提供登录信息(如无则执行设备信息登录): ");
                    Console.ResetColor();
                    string profileImport = Console.ReadLine();
                    if (!string.IsNullOrEmpty(profileImport))
                    {
                        SetAccountInform(profileImport);
                    }
                    else
                    {
                        await LoginAsync();
                    }
                    break;
                default:
                    await GetAnswerAsync();
                    break;
            }
        }

        #endregion

        #region 获取未发布的作业ID

        private static async Task GetUnreleasedHWIDAsync()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("请输入起始作业id: ");
            Console.ResetColor();
            string startInput = Console.ReadLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("请输入截止作业id(小于起始则不会停): ");
            Console.ResetColor();
            string endInput = Console.ReadLine();

            if (!int.TryParse(startInput, out int startHWID) || !int.TryParse(endInput, out int endHWID))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("无效的作业id输入。");
                Console.ResetColor();
                return;
            }

            int hwidPlus100 = startHWID + 100;

            while (true)
            {
                if (startHWID == hwidPlus100)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"已滚动100项 当前 {hwidPlus100}");
                    Console.ResetColor();
                    hwidPlus100 += 100;
                }

                var dataUp = new Dictionary<string, string>
                {
                    { "homeworkId", startHWID.ToString() },
                    { "modifyNum", "0" },
                    { "userId", Id },
                    { "unitId", UnitId }
                };

                string res = await PostAsync("https://padapp.msyk.cn/ws/common/homework/homeworkStatus", dataUp, 3, startHWID.ToString() + "0");
                if (!res.Contains("isWithdrawal"))
                {
                    dynamic json = JsonConvert.DeserializeObject(res);
                    string hwname = json.homeworkName;
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    Console.WriteLine($"{startHWID} {hwname}");
                    Console.ResetColor();
                }

                if (startHWID == endHWID)
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine($"跑作业id结束 当前作业id为 {startHWID}");
                    Console.ResetColor();
                    break;
                }

                startHWID += 1;
            }
        }

        #endregion

        #region 获取作业列表

        private static async Task<List<HomeworkItem>> GetHomeworkListAsync()
        {
            var dataUp = new Dictionary<string, string>
            {
                { "studentId", Id },
                { "subjectCode", "" },
                { "homeworkType", "-1" },
                { "pageIndex", "1" },
                { "pageSize", "36" },
                { "statu", "1" },
                { "homeworkName", "" },
                { "unitId", UnitId }
            };

            string res = await PostAsync("https://padapp.msyk.cn/ws/student/homework/studentHomework/getHomeworkList", dataUp, 2, "-11361");
            dynamic json = JsonConvert.DeserializeObject(res);
            var homeworkList = new List<HomeworkItem>();
            foreach (var item in json.sqHomeworkDtoList)
            {
                homeworkList.Add(new HomeworkItem
                {
                    Id = item.id,
                    HomeworkType = item.homeworkType,
                    HomeworkName = item.homeworkName,
                    EndTime = item.endTime
                });
            }
            return homeworkList;
        }

        #endregion

        #region HomeworkItem 类

        public class HomeworkItem
        {
            public string Id { get; set; }
            public int HomeworkType { get; set; }
            public string HomeworkName { get; set; }
            public long EndTime { get; set; }
        }

        #endregion
    }
}
