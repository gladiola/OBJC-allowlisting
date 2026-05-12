/*
 * i18n.c — Multilingual response strings and Accept-Language detection.
 *
 * Supported locales (BCP 47 primary subtag or full tag):
 *   en  — US English        de  — German          es  — Spanish
 *   fr  — French            pt  — Portuguese       it  — Italian
 *   zh-HK — Hong Kong Chinese (Traditional)        zh  — Mandarin (Simplified)
 *   ko  — Korean            hi  — Hindi            ru  — Russian
 *   ar  — Arabic            sw  — Swahili          ja  — Japanese
 *   ht  — Haitian Creole    haw — Hawaiian         sm  — Samoan
 *   mi  — Māori             af  — Afrikaans        nl  — Dutch
 *   ha  — Hausa             am  — Amharic          yo  — Yoruba
 *   bn  — Bengali           et  — Estonian         fi  — Finnish
 *   sv  — Swedish           no  — Norwegian        uk  — Ukrainian
 *   th  — Thai              id  — Bahasa Indonesia tl  — Tagalog
 *   ms  — Malay             jv  — Javanese         el  — Greek
 *   la  — Latin             he  — Hebrew           ga  — Irish
 */

#include "i18n.h"

#include <ctype.h>
#include <stddef.h>
#include <string.h>

/* ── Per-locale string tables ─────────────────────────────────────────── */

static const LocalizedStrings EN = {
    "OK",
    "403 Forbidden",
    "Request Timeout",
    "Missing REQUEST_METHOD",
    "Invalid configuration path",
    "Internal Server Error",
    "Content-Type must be application/x-www-form-urlencoded",
    "Missing CONTENT_LENGTH",
    "Invalid CONTENT_LENGTH",
    "Request body is not valid UTF-8",
    "Only GET and POST are supported",
    "Failed to load allowlist configuration",
    "Request exceeds size limits"
};

static const LocalizedStrings DE = {
    "OK",
    "403 Verboten",
    "Zeitüberschreitung der Anfrage",
    "REQUEST_METHOD fehlt",
    "Ungültiger Konfigurationspfad",
    "Interner Serverfehler",
    "Content-Type muss application/x-www-form-urlencoded sein",
    "CONTENT_LENGTH fehlt",
    "Ungültige CONTENT_LENGTH",
    "Der Anfragekörper ist kein gültiges UTF-8",
    "Nur GET und POST werden unterstützt",
    "Allowlist-Konfiguration konnte nicht geladen werden",
    "Anfrage überschreitet Größenlimits"
};

static const LocalizedStrings ES = {
    "OK",
    "403 Prohibido",
    "Tiempo de espera agotado",
    "Falta REQUEST_METHOD",
    "Ruta de configuración no válida",
    "Error interno del servidor",
    "Content-Type debe ser application/x-www-form-urlencoded",
    "Falta CONTENT_LENGTH",
    "CONTENT_LENGTH no válido",
    "El cuerpo de la solicitud no es UTF-8 válido",
    "Solo se admiten GET y POST",
    "Error al cargar la configuración de la lista de permisos",
    "La solicitud supera los límites de tamaño"
};

static const LocalizedStrings FR = {
    "OK",
    "403 Interdit",
    "Délai de la requête dépassé",
    "REQUEST_METHOD manquant",
    "Chemin de configuration invalide",
    "Erreur interne du serveur",
    "Content-Type doit être application/x-www-form-urlencoded",
    "CONTENT_LENGTH manquant",
    "CONTENT_LENGTH invalide",
    "Le corps de la requête n'est pas en UTF-8 valide",
    "Seules les méthodes GET et POST sont prises en charge",
    "Échec du chargement de la configuration de la liste d'autorisation",
    "La requête dépasse les limites de taille"
};

static const LocalizedStrings PT = {
    "OK",
    "403 Proibido",
    "Tempo limite da solicitação",
    "REQUEST_METHOD ausente",
    "Caminho de configuração inválido",
    "Erro interno do servidor",
    "Content-Type deve ser application/x-www-form-urlencoded",
    "CONTENT_LENGTH ausente",
    "CONTENT_LENGTH inválido",
    "O corpo da solicitação não é UTF-8 válido",
    "Apenas GET e POST são suportados",
    "Falha ao carregar a configuração da lista de permissões",
    "A solicitação excede os limites de tamanho"
};

static const LocalizedStrings IT = {
    "OK",
    "403 Vietato",
    "Timeout della richiesta",
    "REQUEST_METHOD mancante",
    "Percorso di configurazione non valido",
    "Errore interno del server",
    "Content-Type deve essere application/x-www-form-urlencoded",
    "CONTENT_LENGTH mancante",
    "CONTENT_LENGTH non valido",
    "Il corpo della richiesta non è UTF-8 valido",
    "Solo GET e POST sono supportati",
    "Impossibile caricare la configurazione della lista di autorizzazione",
    "La richiesta supera i limiti di dimensione"
};

/* Traditional Chinese — Hong Kong / Taiwan */
static const LocalizedStrings ZH_HK = {
    "好",
    "403 禁止存取",
    "請求逾時",
    "缺少 REQUEST_METHOD",
    "設定路徑無效",
    "伺服器內部錯誤",
    "Content-Type 必須為 application/x-www-form-urlencoded",
    "缺少 CONTENT_LENGTH",
    "CONTENT_LENGTH 無效",
    "請求主體並非有效的 UTF-8",
    "僅支援 GET 和 POST",
    "無法載入白名單設定",
    "請求超出大小限制"
};

/* Simplified Chinese — Mandarin */
static const LocalizedStrings ZH = {
    "好",
    "403 禁止",
    "请求超时",
    "缺少 REQUEST_METHOD",
    "配置路径无效",
    "服务器内部错误",
    "Content-Type 必须为 application/x-www-form-urlencoded",
    "缺少 CONTENT_LENGTH",
    "CONTENT_LENGTH 无效",
    "请求正文不是有效的 UTF-8",
    "仅支持 GET 和 POST",
    "无法加载许可列表配置",
    "请求超出大小限制"
};

static const LocalizedStrings KO = {
    "확인",
    "403 금지됨",
    "요청 시간 초과",
    "REQUEST_METHOD가 없습니다",
    "잘못된 구성 경로",
    "내부 서버 오류",
    "Content-Type은 application/x-www-form-urlencoded이어야 합니다",
    "CONTENT_LENGTH가 없습니다",
    "잘못된 CONTENT_LENGTH",
    "요청 본문이 유효한 UTF-8이 아닙니다",
    "GET 및 POST만 지원됩니다",
    "허용 목록 구성을 불러오지 못했습니다",
    "요청이 크기 제한을 초과합니다"
};

static const LocalizedStrings HI = {
    "ठीक है",
    "403 प्रतिबंधित",
    "अनुरोध का समय समाप्त",
    "REQUEST_METHOD अनुपस्थित है",
    "अमान्य कॉन्फ़िगरेशन पथ",
    "आंतरिक सर्वर त्रुटि",
    "Content-Type application/x-www-form-urlencoded होना चाहिए",
    "CONTENT_LENGTH अनुपस्थित है",
    "अमान्य CONTENT_LENGTH",
    "अनुरोध मुख्य भाग मान्य UTF-8 नहीं है",
    "केवल GET और POST समर्थित हैं",
    "अनुमति सूची कॉन्फ़िगरेशन लोड करने में विफल",
    "अनुरोध आकार सीमा से अधिक है"
};

static const LocalizedStrings RU = {
    "ОК",
    "403 Запрещено",
    "Время ожидания запроса истекло",
    "REQUEST_METHOD отсутствует",
    "Недопустимый путь конфигурации",
    "Внутренняя ошибка сервера",
    "Content-Type должен быть application/x-www-form-urlencoded",
    "CONTENT_LENGTH отсутствует",
    "Недопустимое значение CONTENT_LENGTH",
    "Тело запроса не является допустимым UTF-8",
    "Поддерживаются только методы GET и POST",
    "Не удалось загрузить конфигурацию списка разрешений",
    "Запрос превышает ограничения по размеру"
};

static const LocalizedStrings AR = {
    "حسناً",
    "403 محظور",
    "انتهت مهلة الطلب",
    "REQUEST_METHOD مفقود",
    "مسار التهيئة غير صالح",
    "خطأ داخلي في الخادم",
    "يجب أن يكون Content-Type هو application/x-www-form-urlencoded",
    "CONTENT_LENGTH مفقود",
    "قيمة CONTENT_LENGTH غير صالحة",
    "نص الطلب ليس UTF-8 صالحاً",
    "يتم دعم GET و POST فقط",
    "فشل تحميل تهيئة قائمة السماح",
    "الطلب يتجاوز حدود الحجم"
};

static const LocalizedStrings SW = {
    "Sawa",
    "403 Imekatazwa",
    "Muda wa ombi umekwisha",
    "REQUEST_METHOD haipo",
    "Njia ya usanidi si sahihi",
    "Hitilafu ya ndani ya seva",
    "Content-Type lazima iwe application/x-www-form-urlencoded",
    "CONTENT_LENGTH haipo",
    "CONTENT_LENGTH si sahihi",
    "Mwili wa ombi si UTF-8 sahihi",
    "GET na POST peke yake zinasaidiwa",
    "Imeshindwa kupakia usanidi wa orodha ya ruhusa",
    "Ombi linazidi mipaka ya ukubwa"
};

static const LocalizedStrings JA = {
    "OK",
    "403 禁止",
    "リクエストタイムアウト",
    "REQUEST_METHOD がありません",
    "設定パスが無効です",
    "内部サーバーエラー",
    "Content-Type は application/x-www-form-urlencoded である必要があります",
    "CONTENT_LENGTH がありません",
    "CONTENT_LENGTH が無効です",
    "リクエストボディが有効な UTF-8 ではありません",
    "GET と POST のみサポートされています",
    "許可リスト設定の読み込みに失敗しました",
    "リクエストがサイズ制限を超えています"
};

static const LocalizedStrings HT = {
    "Dakò",
    "403 Entèdi",
    "Demann an depase tan",
    "REQUEST_METHOD manke",
    "Chemen konfigirasyon an pa valid",
    "Erè entèn sèvè a",
    "Content-Type dwe application/x-www-form-urlencoded",
    "CONTENT_LENGTH manke",
    "CONTENT_LENGTH pa valid",
    "Kò demann an pa UTF-8 valid",
    "Sèlman GET ak POST sipòte",
    "Echèk chajman konfigirasyon lis pèmèt la",
    "Demann an depase limit gwosè"
};

static const LocalizedStrings HAW = {
    "\xca\xbc" "Ae",
    "403 P\xc4\x81p\xc4\x81",
    "Ua pau ka manawa o ka noi",
    "Nalowale ka REQUEST_METHOD",
    "\xca\xbc" "A\xca\xbcole k\xc5\xabpono ke ala ho\xca\xbbonohonoho",
    "Hewa o loko o ke kikowaena",
    "Pono ka Content-Type e like me application/x-www-form-urlencoded",
    "Nalowale ka CONTENT_LENGTH",
    "\xca\xbc" "A\xca\xbcole k\xc5\xabpono ka CONTENT_LENGTH",
    "\xca\xbc" "A\xca\xbcole UTF-8 k\xc5\xabpono ke kino o ka noi",
    "\xca\xbcO GET a me POST wale n\xc5\x8d ka p\xc4\x81p\xc4\x81 \xca\xbcia",
    "Ua h\xc4\x81\xca\xbcule ka ho\xca\xbbouka \xca\xbc" "ana i ka ho\xca\xbbonohonoho papa inoa",
    "Ua hiki ka noi i n\xc4\x81 palena nui"
};

static const LocalizedStrings SM = {
    "Lelei",
    "403 Fa\xca\xbc" "asaina",
    "Ua uma le taimi o le talosaga",
    "Ua leiloa le REQUEST_METHOD",
    "E le sa\xca\xbco le ala o le fa\xca\xbc" "atulagaga",
    "Sa\xca\xbco ses\xc4\x93 faigofie o le server",
    "E tatau ona avea le Content-Type ma application/x-www-form-urlencoded",
    "Ua leiloa le CONTENT_LENGTH",
    "E le sa\xca\xbco le CONTENT_LENGTH",
    "O le tino o le talosaga e le sa\xca\xbco UTF-8",
    "Na\xca\xbco GET ma POST e lagolagoina",
    "Na toilalo le fa\xca\xbc" "auta o le fa\xca\xbc" "atulagaga o le lisi fa\xca\xbc" "atagaina",
    "Ua sili atu le talosaga i le tapula\xca\xbc" "a o le tele"
};

static const LocalizedStrings MI = {
    "\xc4\x80" "e",
    "403 Aukati",
    "Kua mutu te w\xc4\x81 o te tono",
    "K\xc4\x81ore te REQUEST_METHOD",
    "He hapa te ara o te tautuhinga",
    "He hapa \xc4\x81-roto o te t\xc5\xabmau",
    "Me mau te Content-Type ki te application/x-www-form-urlencoded",
    "K\xc4\x81ore te CONTENT_LENGTH",
    "He hapa te CONTENT_LENGTH",
    "Ko te tinana o te tono ehara i te UTF-8 tika",
    "Ko GET me POST an\xc5\x8d e tautokohia ana",
    "I hapa te uta ake i te tautuhinga o te r\xc4\x81rangi whakaaetia",
    "Kua neke atu te tono i ng\xc4\x81 tepenga tae"
};

static const LocalizedStrings AF = {
    "OK",
    "403 Verbode",
    "Versoek tydsduur verstreke",
    "REQUEST_METHOD ontbreek",
    "Ongeldige konfigurasiepad",
    "Interne bedienersfout",
    "Content-Type moet application/x-www-form-urlencoded wees",
    "CONTENT_LENGTH ontbreek",
    "Ongeldige CONTENT_LENGTH",
    "Versoekliggaam is nie geldige UTF-8 nie",
    "Slegs GET en POST word ondersteun",
    "Kon nie allowlys-konfigurasie laai nie",
    "Versoek oorskry groottelimiet"
};

static const LocalizedStrings NL = {
    "OK",
    "403 Verboden",
    "Verzoek time-out",
    "REQUEST_METHOD ontbreekt",
    "Ongeldig configuratiepad",
    "Interne serverfout",
    "Content-Type moet application/x-www-form-urlencoded zijn",
    "CONTENT_LENGTH ontbreekt",
    "Ongeldige CONTENT_LENGTH",
    "De aanvraagbody is geen geldige UTF-8",
    "Alleen GET en POST worden ondersteund",
    "Laden van allowlist-configuratie mislukt",
    "Verzoek overschrijdt groottelimieten"
};

static const LocalizedStrings HA = {
    "Lafiya",
    "403 Haramun",
    "Lokacin bu\xc6\x99" "ata ya \xc6\x99" "are",
    "REQUEST_METHOD ba ya nan",
    "Hanyar saitin ba daidai ba",
    "Kuskuren uwar garke na ciki",
    "Content-Type dole ne ya zama application/x-www-form-urlencoded",
    "CONTENT_LENGTH ba ya nan",
    "CONTENT_LENGTH ba daidai ba",
    "Jikin bu\xc6\x99" "atar ba UTF-8 sahihi ba ne",
    "GET da POST ne kawai ake marawa baya",
    "An kasa loda saitin jerin izini",
    "Bu\xc6\x99" "atar ta zarce \xc6\x99" "ayyadaddun girma"
};

static const LocalizedStrings AM = {
    "\xe1\x8a\xa5\xe1\x88\xbc",
    "403 \xe1\x8b\xab\xe1\x8c\x88\xe1\x8b\x88 \xe1\x8b\x88\xe1\x88\x8b\xe1\x89\x80\xe1\x88\x88",
    "\xe1\x8b\xae\xe1\x8a\xa5\xe1\x8b\x8d\xe1\x88\x8c \xe1\x8c\x8a\xe1\x8b\x9c \xe1\x8a\xa0\xe1\x88\x8d\xe1\x8d\x8b\xe1\x88\x8d",
    "REQUEST_METHOD \xe1\x8c\xa0\xe1\x8d\x8d\xe1\x89\xa7\xe1\x88\x8d",
    "\xe1\x88\x8d\xe1\x8a\xad \xe1\x8b\xab\xe1\x88\x8d\xe1\x88\x86\xe1\x8a\x90 \xe1\x8b\xae\xe1\x88\x9b\xe1\x8b\x8b\xe1\x88\xb0\xe1\x88\xad \xe1\x88\xb5\xe1\x88\x85\xe1\x8b\x98\xe1\x89\xb5",
    "\xe1\x8b\xae\xe1\x8b\x8d\xe1\x88\xb5\xe1\x8b\x8d \xe1\x8a\xa0\xe1\x8c\x88\xe1\x88\x8d\xe1\x8c\x8b\xe1\x8b\x8d \xe1\x88\xb5\xe1\x88\x85\xe1\x89\xb0\xe1\x89\xb5",
    "Content-Type application/x-www-form-urlencoded \xe1\x88\x98\xe1\x88\x86\xe1\x8a\x90 \xe1\x8a\xa0\xe1\x88\x88\xe1\x89\xa0\xe1\x89\xb5",
    "CONTENT_LENGTH \xe1\x8c\xa0\xe1\x8d\x8d\xe1\x89\xa7\xe1\x88\x8d",
    "\xe1\x88\x8d\xe1\x8a\xad \xe1\x8b\xab\xe1\x88\x8d\xe1\x88\x86\xe1\x8a\x90 CONTENT_LENGTH",
    "\xe1\x8b\xae\xe1\x8b\x8d\xe1\x88\x8d\xe1\x8b\x8f\xe1\x89\xb5 \xe1\x89\xb5\xe1\x8a\xad\xe1\x8a\xab\xe1\x8c\xa3\xe1\x8a\x9b \xe1\x88\x88\xe1\x8d\x8b UTF-8 \xe1\x8a\xa0\xe1\x8b\xad\xe1\x8b\xb0\xe1\x88\x8d\xe1\x88\x9d",
    "GET \xe1\x8a\xa5\xe1\x8a\x93 POST \xe1\x89\xa5\xe1\x89\xb3 \xe1\x8b\xad\xe1\x8b\xb0\xe1\x88\x88\xe1\x8d\x8b\xe1\x88\x8d",
    "\xe1\x8b\xae\xe1\x8d\x8d\xe1\x89\xb3\xe1\x8d\x8d \xe1\x8d\x90\xe1\x88\x88\xe1\x89\xb0\xe1\x89\xb5 \xe1\x88\x80\xe1\x8b\x98\xe1\x8b\x98\xe1\x88\x8d \xe1\x89\x80\xe1\x88\x8b\xe1\x89\xb5 \xe1\x8d\x88\xe1\x88\xa8\xe1\x88\x9d \xe1\x8a\xa0\xe1\x88\x8d\xe1\x89\xb3\xe1\x8c\x88\xe1\x88\x98",
    "\xe1\x8c\xa5\xe1\x8b\x8b\xe1\x8e\xad \xe1\x8b\xae\xe1\x88\x98\xe1\x8c\xa5 \xe1\x88\x88\xe1\x8c\xb3\xe1\x8a\x9d \xe1\x8b\xaa\xe1\x8d\x8b\xe1\x88\x8d"
};

static const LocalizedStrings YO = {
    "O d\xc3\xa1ra",
    "403 \xc3\x88w\xe1\xbb\x8d\xcc\x80",
    "\xc3\x80k\xc3\xb3k\xc3\xb2 \xc3\xac" "b\xc3\xa9\xc3\xa8rere ti pari",
    "REQUEST_METHOD k\xc3\xb2 s\xc3\xad",
    "\xe1\xbb\x8c\xcc\x80n\xc3\xa0 is\xe1\xba\xb9\xcc\x80t\xc3\xb2 k\xc3\xb2 t\xe1\xbb\x8d\xcc\x81",
    "\xc3\x80s\xc3\xacs\xe1\xba\xb9 \xc3\xacn\xc3\xb9 s\xe1\xba\xb9r\xc3\xb9\xc3\xba" "fw\xc3\xb9",
    "Content-Type gb\xe1\xbb\x8d" "d\xe1\xbb\x8d j\xe1\xba\xb9\xcc\x80 application/x-www-form-urlencoded",
    "CONTENT_LENGTH k\xc3\xb2 s\xc3\xad",
    "CONTENT_LENGTH k\xc3\xb2 t\xe1\xbb\x8d\xcc\x81",
    "\xc3\x8ck\xc3\xban\xc3\xa0 \xc3\xac" "b\xc3\xa9\xc3\xa8rere k\xc3\xb2 j\xe1\xba\xb9\xcc\x80 UTF-8 t\xc3\xb3 t\xe1\xbb\x8d\xcc\x81",
    "\xc3\x80w\xe1\xbb\x8dn GET \xc3\xa0t\xc3\xac POST n\xc3\xackan ni a s\xe1\xba\xb9 \xc3\xa0t\xc3\xacl\xe1\xba\xb9\xcc\x81y\xc3\xacn",
    "K\xc3\xb2 le gb\xc3\xa9 \xc3\xacs\xe1\xba\xb9\xcc\x80t\xc3\xb2 \xc3\xa0k\xc3\xb3j\xe1\xbb\x8d \xc3\xa0s\xe1\xba\xb9\xcc\x80",
    "\xc3\x8c" "b\xc3\xa9\xc3\xa8rere j\xc3\xb9 \xc3\xa0w\xe1\xbb\x8dn \xc3\xacgb\xc3\xa9kal\xe1\xba\xb9\xcc\x80 iwon l\xe1\xbb\x8d"
};

static const LocalizedStrings BN = {
    "\xe0\xa6\xa0\xe0\xa6\xbf\xe0\xa6\x95 \xe0\xa6\x86\xe0\xa6\x9b\xe0\xa7\x87",
    "403 \xe0\xa6\xa8\xe0\xa6\xbf\xe0\xa6\xb7\xe0\xa6\xbf\xe0\xa6\xa6\xe0\xa7\x8d\xe0\xa6\xa7",
    "\xe0\xa6\x85\xe0\xa6\xa8\xe0\xa7\x81\xe0\xa6\xb0\xe0\xa7\x8b\xe0\xa6\xa7\xe0\xa7\x87\xe0\xa6\xb0 \xe0\xa6\xb8\xe0\xa6\xae\xe0\xa6\xaf\xe0\xa6\xbc \xe0\xa6\xb6\xe0\xa7\x87\xe0\xa6\xb7",
    "REQUEST_METHOD \xe0\xa6\x85\xe0\xa6\xa8\xe0\xa7\x81\xe0\xa6\xaa\xe0\xa6\xb8\xe0\xa7\x8d\xe0\xa6\xa5\xe0\xa6\xbf\xe0\xa6\xa4",
    "\xe0\xa6\x85\xe0\xa6\xac\xe0\xa7\x88\xe0\xa6\xa7 \xe0\xa6\x95\xe0\xa6\xa8\xe0\xa6\xab\xe0\xa6\xbf\xe0\xa6\x97\xe0\xa6\xbe\xe0\xa6\xb0\xe0\xa7\x87\xe0\xa6\xb6\xe0\xa6\xa8 \xe0\xa6\xaa\xe0\xa6\xa5",
    "\xe0\xa6\x85\xe0\xa6\xad\xe0\xa7\x8d\xe0\xa6\xaf\xe0\xa6\xa8\xe0\xa7\x8d\xe0\xa6\xa4\xe0\xa6\xb0\xe0\xa7\x80\xe0\xa6\xa3 \xe0\xa6\xb8\xe0\xa6\xbe\xe0\xa6\xb0\xe0\xa7\x8d\xe0\xa6\xad\xe0\xa6\xbe\xe0\xa6\xb0 \xe0\xa6\xa4\xe0\xa7\x8d\xe0\xa6\xb0\xe0\xa7\x81\xe0\xa6\x9f\xe0\xa6\xbf",
    "Content-Type \xe0\xa6\x85\xe0\xa6\xac\xe0\xa6\xb6\xe0\xa7\x8d\xe0\xa6\xaf\xe0\xa6\x87 application/x-www-form-urlencoded \xe0\xa6\xb9\xe0\xa6\xa4\xe0\xa7\x87 \xe0\xa6\xb9\xe0\xa6\xac\xe0\xa7\x87",
    "CONTENT_LENGTH \xe0\xa6\x85\xe0\xa6\xa8\xe0\xa7\x81\xe0\xa6\xaa\xe0\xa6\xb8\xe0\xa7\x8d\xe0\xa6\xa5\xe0\xa6\xbf\xe0\xa6\xa4",
    "\xe0\xa6\x85\xe0\xa6\xac\xe0\xa7\x88\xe0\xa6\xa7 CONTENT_LENGTH",
    "\xe0\xa6\x85\xe0\xa6\xa8\xe0\xa7\x81\xe0\xa6\xb0\xe0\xa7\x8b\xe0\xa6\xa7\xe0\xa7\x87\xe0\xa6\xb0 \xe0\xa6\xac\xe0\xa6\xa1\xe0\xa6\xbf \xe0\xa6\xac\xe0\xa7\x88\xe0\xa6\xa7 UTF-8 \xe0\xa6\xa8\xe0\xa6\xaf\xe0\xa6\xbc",
    "\xe0\xa6\xb6\xe0\xa7\x81\xe0\xa6\xa7\xe0\xa7\x81\xe0\xa6\xae\xe0\xa6\xbe\xe0\xa6\xa4\xe0\xa7\x8d\xe0\xa6\xb0 GET \xe0\xa6\x8f\xe0\xa6\xac\xe0\xa6\x82 POST \xe0\xa6\xb8\xe0\xa6\xae\xe0\xa6\xb0\xe0\xa7\x8d\xe0\xa6\xa5\xe0\xa6\xbf\xe0\xa6\xa4",
    "\xe0\xa6\x85\xe0\xa6\xa8\xe0\xa7\x81\xe0\xa6\xae\xe0\xa6\xa4\xe0\xa6\xbf \xe0\xa6\xa4\xe0\xa6\xbe\xe0\xa6\xb2\xe0\xa6\xbf\xe0\xa6\x95\xe0\xa6\xbe \xe0\xa6\x95\xe0\xa6\xa8\xe0\xa6\xab\xe0\xa6\xbf\xe0\xa6\x97\xe0\xa6\xbe\xe0\xa6\xb0\xe0\xa7\x87\xe0\xa6\xb6\xe0\xa6\xa8 \xe0\xa6\xb2\xe0\xa7\x8b\xe0\xa6\xa1 \xe0\xa6\x95\xe0\xa6\xb0\xe0\xa6\xa4\xe0\xa7\x87 \xe0\xa6\xac\xe0\xa7\x8d\xe0\xa6\xaf\xe0\xa6\xb0\xe0\xa7\x8d\xe0\xa6\xa5",
    "\xe0\xa6\x85\xe0\xa6\xa8\xe0\xa7\x81\xe0\xa6\xb0\xe0\xa7\x8b\xe0\xa6\xa7 \xe0\xa6\x86\xe0\xa6\x95\xe0\xa6\xbe\xe0\xa6\xb0\xe0\xa7\x87\xe0\xa6\xb0 \xe0\xa6\xb8\xe0\xa7\x80\xe0\xa6\xae\xe0\xa6\xbe \xe0\xa6\x85\xe0\xa6\xa4\xe0\xa6\xbf\xe0\xa6\x95\xe0\xa7\x8d\xe0\xa6\xb0\xe0\xa6\xae \xe0\xa6\x95\xe0\xa6\xb0\xe0\xa7\x87\xe0\xa6\x9b\xe0\xa7\x87"
};

static const LocalizedStrings ET = {
    "OK",
    "403 Keelatud",
    "P\xc3\xa4ringu ajalõpp",
    "REQUEST_METHOD puudub",
    "Vigane konfiguratsiooni tee",
    "Sisemine serveriviga",
    "Content-Type peab olema application/x-www-form-urlencoded",
    "CONTENT_LENGTH puudub",
    "Vigane CONTENT_LENGTH",
    "P\xc3\xa4ringu keha ei ole kehtiv UTF-8",
    "Toetatakse ainult GET ja POST meetodeid",
    "Lubatud loendi konfiguratsiooni laadimine eba\xc3\xb5nnestus",
    "P\xc3\xa4ring \xc3\xbcletab suuruspiirangud"
};

static const LocalizedStrings FI = {
    "OK",
    "403 Kielletty",
    "Pyynt\xc3\xb6 aikakatkaistiin",
    "REQUEST_METHOD puuttuu",
    "Virheellinen konfiguraatiopolku",
    "Sis\xc3\xa4inen palvelinvirhe",
    "Content-Type t\xc3\xa4ytyy olla application/x-www-form-urlencoded",
    "CONTENT_LENGTH puuttuu",
    "Virheellinen CONTENT_LENGTH",
    "Pyynn\xc3\xb6n runko ei ole kelvollista UTF-8:aa",
    "Vain GET ja POST ovat tuettuja",
    "Sallittujen luettelon konfiguraation lataus ep\xc3\xa4onnistui",
    "Pyyn\xc3\xb6 ylitt\xc3\xa4\xc3\xa4 kokorajoitukset"
};

static const LocalizedStrings SV = {
    "OK",
    "403 F\xc3\xb6rbjudet",
    "Beg\xc3\xa4ran tog f\xc3\xb6r l\xc3\xa5ng tid",
    "REQUEST_METHOD saknas",
    "Ogiltig konfigurationss\xc3\xb6kv\xc3\xa4g",
    "Internt serverfel",
    "Content-Type m\xc3\xa5ste vara application/x-www-form-urlencoded",
    "CONTENT_LENGTH saknas",
    "Ogiltig CONTENT_LENGTH",
    "Beg\xc3\xa4rans br\xc3\xb6" "dtext \xc3\xa4r inte giltig UTF-8",
    "Endast GET och POST st\xc3\xb6" "ds",
    "Det gick inte att l\xc3\xa4sa in konfigurationen f\xc3\xb6r till\xc3\xa5telselistan",
    "Beg\xc3\xa4ran \xc3\xb6verskrider storleksgr\xc3\xa4nserna"
};

static const LocalizedStrings NO = {
    "OK",
    "403 Forbudt",
    "Foresp\xc3\xb8rselen fikk tidsavbrudd",
    "REQUEST_METHOD mangler",
    "Ugyldig konfigurasjonssti",
    "Intern serverfeil",
    "Content-Type m\xc3\xa5 v\xc3\xa6re application/x-www-form-urlencoded",
    "CONTENT_LENGTH mangler",
    "Ugyldig CONTENT_LENGTH",
    "Foresp\xc3\xb8rselskroppen er ikke gyldig UTF-8",
    "Bare GET og POST st\xc3\xb8ttes",
    "Klarte ikke \xc3\xa5 laste inn tillatelsesliste-konfigurasjonen",
    "Foresp\xc3\xb8rselen overskrider st\xc3\xb8rrelsesbegrensningene"
};

static const LocalizedStrings UK = {
    "\xd0\x94\xd0\xbe\xd0\xb1\xd1\x80\xd0\xb5",
    "403 \xd0\x97\xd0\xb0\xd0\xb1\xd0\xbe\xd1\x80\xd0\xbe\xd0\xbd\xd0\xb5\xd0\xbd\xd0\xbe",
    "\xd0\xa7\xd0\xb0\xd1\x81 \xd0\xbe\xd1\x87\xd1\x96\xd0\xba\xd1\x83\xd0\xb2\xd0\xb0\xd0\xbd\xd0\xbd\xd1\x8f \xd0\xb7\xd0\xb0\xd0\xbf\xd0\xb8\xd1\x82\xd1\x83 \xd0\xb2\xd0\xb8\xd1\x87\xd0\xb5\xd1\x80\xd0\xbf\xd0\xb0\xd0\xbd\xd0\xbe",
    "REQUEST_METHOD \xd0\xb2\xd1\x96\xd0\xb4\xd1\x81\xd1\x83\xd1\x82\xd0\xbd\xd1\x96\xd0\xb9",
    "\xd0\x9d\xd0\xb5\xd0\xb4\xd1\x96\xd0\xb9\xd1\x81\xd0\xbd\xd0\xb8\xd0\xb9 \xd1\x88\xd0\xbb\xd1\x8f\xd1\x85 \xd0\xba\xd0\xbe\xd0\xbd\xd1\x84\xd1\x96\xd0\xb3\xd1\x83\xd1\x80\xd0\xb0\xd1\x86\xd1\x96\xd1\x97",
    "\xd0\x92\xd0\xbd\xd1\x83\xd1\x82\xd1\x80\xd1\x96\xd1\x88\xd0\xbd\xd1\x8f \xd0\xbf\xd0\xbe\xd0\xbc\xd0\xb8\xd0\xbb\xd0\xba\xd0\xb0 \xd1\x81\xd0\xb5\xd1\x80\xd0\xb2\xd0\xb5\xd1\x80\xd0\xb0",
    "Content-Type \xd0\xbc\xd0\xb0\xd1\x94 \xd0\xb1\xd1\x83\xd1\x82\xd0\xb8 application/x-www-form-urlencoded",
    "CONTENT_LENGTH \xd0\xb2\xd1\x96\xd0\xb4\xd1\x81\xd1\x83\xd1\x82\xd0\xbd\xd1\x96\xd0\xb9",
    "\xd0\x9d\xd0\xb5\xd0\xb4\xd1\x96\xd0\xb9\xd1\x81\xd0\xbd\xd0\xb8\xd0\xb9 CONTENT_LENGTH",
    "\xd0\xa2\xd1\x96\xd0\xbb\xd0\xbe \xd0\xb7\xd0\xb0\xd0\xbf\xd0\xb8\xd1\x82\xd1\x83 \xd0\xbd\xd0\xb5 \xd1\x94 \xd0\xb4\xd1\x96\xd0\xb9\xd1\x81\xd0\xbd\xd0\xb8\xd0\xbc UTF-8",
    "\xd0\x9f\xd1\x96\xd0\xb4\xd1\x82\xd1\x80\xd0\xb8\xd0\xbc\xd1\x83\xd1\x8e\xd1\x82\xd1\x8c\xd1\x81\xd1\x8f \xd0\xbb\xd0\xb8\xd1\x88\xd0\xb5 GET \xd1\x96 POST",
    "\xd0\x9d\xd0\xb5 \xd0\xb2\xd0\xb4\xd0\xb0\xd0\xbb\xd0\xbe\xd1\x81\xd1\x8f \xd0\xb7\xd0\xb0\xd0\xb2\xd0\xb0\xd0\xbd\xd1\x82\xd0\xb0\xd0\xb6\xd0\xb8\xd1\x82\xd0\xb8 \xd0\xba\xd0\xbe\xd0\xbd\xd1\x84\xd1\x96\xd0\xb3\xd1\x83\xd1\x80\xd0\xb0\xd1\x86\xd1\x96\xd1\x8e \xd1\x81\xd0\xbf\xd0\xb8\xd1\x81\xd0\xba\xd1\x83 \xd0\xb4\xd0\xbe\xd0\xb7\xd0\xb2\xd0\xbe\xd0\xbb\xd0\xb5\xd0\xbd\xd0\xb8\xd1\x85",
    "\xd0\x97\xd0\xb0\xd0\xbf\xd0\xb8\xd1\x82 \xd0\xbf\xd0\xb5\xd1\x80\xd0\xb5\xd0\xb2\xd0\xb8\xd1\x89\xd1\x83\xd1\x94 \xd0\xbe\xd0\xb1\xd0\xbc\xd0\xb5\xd0\xb6\xd0\xb5\xd0\xbd\xd0\xbd\xd1\x8f \xd1\x80\xd0\xbe\xd0\xb7\xd0\xbc\xd1\x96\xd1\x80\xd1\x83"
};

static const LocalizedStrings TH = {
    "\xe0\xb8\x95\xe0\xb8\x81\xe0\xb8\xa5\xe0\xb8\x87",
    "403 \xe0\xb8\x96\xe0\xb8\xb9\xe0\xb8\x81\xe0\xb8\xab\xe0\xb9\x89\xe0\xb8\xb2\xe0\xb8\xa1",
    "\xe0\xb8\x84\xe0\xb8\xb3\xe0\xb8\x82\xe0\xb8\xad\xe0\xb8\xab\xe0\xb8\xa1\xe0\xb8\x94\xe0\xb9\x80\xe0\xb8\xa7\xe0\xb8\xa5\xe0\xb8\xb2",
    "\xe0\xb9\x84\xe0\xb8\xa1\xe0\xb9\x88\xe0\xb8\xa1\xe0\xb8\xb5 REQUEST_METHOD",
    "\xe0\xb9\x80\xe0\xb8\xaa\xe0\xb9\x89\xe0\xb8\x99\xe0\xb8\x97\xe0\xb8\xb2\xe0\xb8\x87\xe0\xb8\x81\xe0\xb8\xb2\xe0\xb8\xa3\xe0\xb8\x81\xe0\xb8\xb3\xe0\xb8\xab\xe0\xb8\x99\xe0\xb8\x94\xe0\xb8\x84\xe0\xb9\x88\xe0\xb8\xb2\xe0\xb9\x84\xe0\xb8\xa1\xe0\xb9\x88\xe0\xb8\x96\xe0\xb8\xb9\xe0\xb8\x81\xe0\xb8\x95\xe0\xb9\x89\xe0\xb8\xad\xe0\xb8\x87",
    "\xe0\xb9\x80\xe0\xb8\x81\xe0\xb8\xb4\xe0\xb8\x94\xe0\xb8\x82\xe0\xb9\x89\xe0\xb8\xad\xe0\xb8\x9c\xe0\xb8\xb4\xe0\xb8\x94\xe0\xb8\x9e\xe0\xb8\xa5\xe0\xb8\xb2\xe0\xb8\x94\xe0\xb8\xa0\xe0\xb8\xb2\xe0\xb8\xa2\xe0\xb9\x83\xe0\xb8\x99\xe0\xb9\x80\xe0\xb8\x8b\xe0\xb8\xb4\xe0\xb8\xa3\xe0\xb9\x8c\xe0\xb8\x9f\xe0\xb9\x80\xe0\xb8\xa7\xe0\xb8\xad\xe0\xb8\xa3\xe0\xb9\x8c",
    "Content-Type \xe0\xb8\x95\xe0\xb9\x89\xe0\xb8\xad\xe0\xb8\x87\xe0\xb9\x80\xe0\xb8\x9b\xe0\xb9\x87\xe0\xb8\x99 application/x-www-form-urlencoded",
    "\xe0\xb9\x84\xe0\xb8\xa1\xe0\xb9\x88\xe0\xb8\xa1\xe0\xb8\xb5 CONTENT_LENGTH",
    "CONTENT_LENGTH \xe0\xb9\x84\xe0\xb8\xa1\xe0\xb9\x88\xe0\xb8\x96\xe0\xb8\xb9\xe0\xb8\x81\xe0\xb8\x95\xe0\xb9\x89\xe0\xb8\xad\xe0\xb8\x87",
    "\xe0\xb9\x80\xe0\xb8\x99\xe0\xb8\xb7\xe0\xb9\x89\xe0\xb8\xad\xe0\xb8\xab\xe0\xb8\xb2\xe0\xb8\x84\xe0\xb8\xb3\xe0\xb8\x82\xe0\xb8\xad\xe0\xb9\x84\xe0\xb8\xa1\xe0\xb9\x88\xe0\xb9\x83\xe0\xb8\x8a\xe0\xb9\x88 UTF-8 \xe0\xb8\x97\xe0\xb8\xb5\xe0\xb9\x88\xe0\xb8\x96\xe0\xb8\xb9\xe0\xb8\x81\xe0\xb8\x95\xe0\xb9\x89\xe0\xb8\xad\xe0\xb8\x87",
    "\xe0\xb8\xa3\xe0\xb8\xad\xe0\xb8\x87\xe0\xb8\xa3\xe0\xb8\xb1\xe0\xb8\x9a\xe0\xb9\x80\xe0\xb8\x89\xe0\xb8\x9e\xe0\xb8\xb2\xe0\xb8\xb0 GET \xe0\xb9\x81\xe0\xb8\xa5\xe0\xb8\xb0 POST \xe0\xb9\x80\xe0\xb8\x97\xe0\xb9\x88\xe0\xb8\xb2\xe0\xb8\x99\xe0\xb8\xb1\xe0\xb9\x89\xe0\xb8\x99",
    "\xe0\xb9\x84\xe0\xb8\xa1\xe0\xb9\x88\xe0\xb8\xaa\xe0\xb8\xb2\xe0\xb8\xa1\xe0\xb8\xb2\xe0\xb8\xa3\xe0\xb8\x96\xe0\xb9\x82\xe0\xb8\xab\xe0\xb8\xa5\xe0\xb8\x94\xe0\xb8\x81\xe0\xb8\xb2\xe0\xb8\xa3\xe0\xb8\x81\xe0\xb8\xb3\xe0\xb8\xab\xe0\xb8\x99\xe0\xb8\x94\xe0\xb8\x84\xe0\xb9\x88\xe0\xb8\xb2\xe0\xb8\xa3\xe0\xb8\xb2\xe0\xb8\xa2\xe0\xb8\x81\xe0\xb8\xb2\xe0\xb8\xa3\xe0\xb8\x97\xe0\xb8\xb5\xe0\xb9\x88\xe0\xb8\xad\xe0\xb8\x99\xe0\xb8\xb8\xe0\xb8\x8d\xe0\xb8\xb2\xe0\xb8\x95\xe0\xb9\x84\xe0\xb8\x94\xe0\xb9\x89",
    "\xe0\xb8\x84\xe0\xb8\xb3\xe0\xb8\x82\xe0\xb8\xad\xe0\xb9\x80\xe0\xb8\x81\xe0\xb8\xb4\xe0\xb8\x99\xe0\xb8\x82\xe0\xb8\xb5\xe0\xb8\x94\xe0\xb8\x88\xe0\xb8\xb3\xe0\xb8\x81\xe0\xb8\xb1\xe0\xb8\x94\xe0\xb8\x82\xe0\xb8\x99\xe0\xb8\xb2\xe0\xb8\x94"
};

static const LocalizedStrings ID = {
    "OK",
    "403 Dilarang",
    "Waktu permintaan habis",
    "REQUEST_METHOD tidak ada",
    "Jalur konfigurasi tidak valid",
    "Kesalahan server internal",
    "Content-Type harus application/x-www-form-urlencoded",
    "CONTENT_LENGTH tidak ada",
    "CONTENT_LENGTH tidak valid",
    "Badan permintaan bukan UTF-8 yang valid",
    "Hanya GET dan POST yang didukung",
    "Gagal memuat konfigurasi daftar yang diizinkan",
    "Permintaan melebihi batas ukuran"
};

static const LocalizedStrings TL = {
    "Sige",
    "403 Ipinagbabawal",
    "Nag-timeout ang kahilingan",
    "Wala ang REQUEST_METHOD",
    "Hindi valid ang configuration path",
    "Panloob na error ng server",
    "Ang Content-Type ay dapat na application/x-www-form-urlencoded",
    "Wala ang CONTENT_LENGTH",
    "Hindi valid ang CONTENT_LENGTH",
    "Ang katawan ng kahilingan ay hindi valid na UTF-8",
    "GET at POST lamang ang sinusuportahan",
    "Nabigo ang pag-load ng configuration ng allowlist",
    "Nalampasan ng kahilingan ang mga limitasyon sa laki"
};

static const LocalizedStrings MS = {
    "OK",
    "403 Dilarang",
    "Masa permintaan tamat",
    "REQUEST_METHOD tiada",
    "Laluan konfigurasi tidak sah",
    "Ralat pelayan dalaman",
    "Content-Type mestilah application/x-www-form-urlencoded",
    "CONTENT_LENGTH tiada",
    "CONTENT_LENGTH tidak sah",
    "Badan permintaan bukan UTF-8 yang sah",
    "Hanya GET dan POST disokong",
    "Gagal memuatkan konfigurasi senarai yang dibenarkan",
    "Permintaan melebihi had saiz"
};

static const LocalizedStrings JV = {
    "Oke",
    "403 Dilarang",
    "Wektu panjaluk entek",
    "REQUEST_METHOD ora ana",
    "Jalur konfigurasi ora sah",
    "Kesalahan server internal",
    "Content-Type kudu application/x-www-form-urlencoded",
    "CONTENT_LENGTH ora ana",
    "CONTENT_LENGTH ora sah",
    "Awak panjaluk dudu UTF-8 sing sah",
    "Mung GET lan POST sing didhukung",
    "Gagal ngemot konfigurasi dhaftar sing diijinake",
    "Panjaluk ngluwihi wates ukuran"
};

static const LocalizedStrings EL = {
    "\xce\x95\xce\xbd\xcf\x84\xce\xac\xce\xbe\xce\xb5\xce\xb9",
    "403 \xce\x91\xcf\x80\xce\xb1\xce\xb3\xce\xbf\xcf\x81\xce\xb5\xcf\x85\xce\xbc\xce\xad\xce\xbd\xce\xbf",
    "\xce\x9b\xce\xae\xce\xbe\xce\xb7 \xcf\x87\xcf\x81\xcf\x8c\xce\xbd\xce\xbf\xcf\x85 \xce\xb1\xce\xb9\xcf\x84\xce\xae\xce\xbc\xce\xb1\xcf\x84\xce\xbf\xcf\x82",
    "\xce\x9b\xce\xb5\xce\xaf\xcf\x80\xce\xb5\xce\xb9 \xcf\x84\xce\xbf REQUEST_METHOD",
    "\xce\x9c\xce\xb7 \xce\xad\xce\xb3\xce\xba\xcf\x85\xcf\x81\xce\xb7 \xce\xb4\xce\xb9\xce\xb1\xce\xb4\xcf\x81\xce\xbf\xce\xbc\xce\xae \xce\xb4\xce\xb9\xce\xb1\xce\xbc\xcf\x8c\xcf\x81\xcf\x86\xcf\x89\xcf\x83\xce\xb7\xcf\x82",
    "\xce\x95\xcf\x83\xcf\x89\xcf\x84\xce\xb5\xcf\x81\xce\xb9\xce\xba\xcf\x8c \xcf\x83\xcf\x86\xce\xac\xce\xbb\xce\xbc\xce\xb1 \xce\xb4\xce\xb9\xce\xb1\xce\xba\xce\xbf\xce\xbc\xce\xb9\xcf\x83\xcf\x84\xce\xae",
    "\xce\xa4\xce\xbf Content-Type \xcf\x80\xcf\x81\xce\xad\xcf\x80\xce\xb5\xce\xb9 \xce\xbd\xce\xb1 \xce\xb5\xce\xaf\xce\xbd\xce\xb1\xce\xb9 application/x-www-form-urlencoded",
    "\xce\x9b\xce\xb5\xce\xaf\xcf\x80\xce\xb5\xce\xb9 \xcf\x84\xce\xbf CONTENT_LENGTH",
    "\xce\x9c\xce\xb7 \xce\xad\xce\xb3\xce\xba\xcf\x85\xcf\x81\xce\xbf CONTENT_LENGTH",
    "\xce\xa4\xce\xbf \xcf\x83\xcf\x8e\xce\xbc\xce\xb1 \xcf\x84\xce\xbf\xcf\x85 \xce\xb1\xce\xb9\xcf\x84\xce\xae\xce\xbc\xce\xb1\xcf\x84\xce\xbf\xcf\x82 \xce\xb4\xce\xb5\xce\xbd \xce\xb5\xce\xaf\xce\xbd\xce\xb1\xce\xb9 \xce\xad\xce\xb3\xce\xba\xcf\x85\xcf\x81\xce\xbf UTF-8",
    "\xce\xa5\xcf\x80\xce\xbf\xcf\x83\xcf\x84\xce\xb7\xcf\x81\xce\xaf\xce\xb6\xce\xbf\xce\xbd\xcf\x84\xce\xb1\xce\xb9 \xce\xbc\xcf\x8c\xce\xbd\xce\xbf GET \xce\xba\xce\xb1\xce\xb9 POST",
    "\xce\x91\xcf\x80\xce\xbf\xcf\x84\xcf\x85\xcf\x87\xce\xaf\xce\xb1 \xcf\x86\xcf\x8c\xcf\x81\xcf\x84\xcf\x89\xcf\x83\xce\xb7\xcf\x82 \xce\xb4\xce\xb9\xce\xb1\xce\xbc\xcf\x8c\xcf\x81\xcf\x86\xcf\x89\xcf\x83\xce\xb7\xcf\x82 \xce\xbb\xce\xaf\xcf\x83\xcf\x84\xce\xb1\xcf\x82 \xce\xb5\xcf\x80\xce\xb9\xcf\x84\xcf\x81\xce\xb5\xcf\x80\xcf\x8c\xce\xbc\xce\xb5\xce\xbd\xcf\x89\xce\xbd",
    "\xce\xa4\xce\xbf \xce\xb1\xce\xaf\xcf\x84\xce\xb7\xce\xbc\xce\xb1 \xcf\x85\xcf\x80\xce\xb5\xcf\x81\xce\xb2\xce\xb1\xce\xaf\xce\xbd\xce\xb5\xce\xb9 \xcf\x84\xce\xb1 \xcf\x8c\xcf\x81\xce\xb9\xce\xb1 \xce\xbc\xce\xb5\xce\xb3\xce\xad\xce\xb8\xce\xbf\xcf\x85\xcf\x82"
};

static const LocalizedStrings LA = {
    "Bene",
    "403 Vetitum",
    "Tempus petitionis excessum",
    "REQUEST_METHOD deest",
    "Iter configurationis invalidum",
    "Error internus servi",
    "Content-Type esse debet application/x-www-form-urlencoded",
    "CONTENT_LENGTH deest",
    "CONTENT_LENGTH invalidum",
    "Corpus petitionis UTF-8 validum non est",
    "Solum GET et POST sustinetur",
    "Oneratio configurationis indicis permissorum defecit",
    "Petitio limites magnitudinis excedit"
};

static const LocalizedStrings HE = {
    "\xd7\x91\xd7\xa1\xd7\x93\xd7\xa8",
    "403 \xd7\x90\xd7\xa1\xd7\x95\xd7\xa8",
    "\xd7\xa4\xd7\xa1\xd7\xa7 \xd7\x96\xd7\x9e\xd7\x9f \xd7\x94\xd7\x91\xd7\xa7\xd7\xa9\xd7\x94",
    "REQUEST_METHOD \xd7\x97\xd7\xa1\xd7\xa8",
    "\xd7\xa0\xd7\xaa\xd7\x99\xd7\x91 \xd7\xaa\xd7\xa6\xd7\x95\xd7\xa8\xd7\x94 \xd7\x9c\xd7\x90 \xd7\x97\xd7\x95\xd7\xa7\xd7\x99",
    "\xd7\xa9\xd7\x92\xd7\x99\xd7\x90\xd7\xaa \xd7\xa9\xd7\xa8\xd7\xaa \xd7\xa4\xd7\xa0\xd7\x99\xd7\x9e\xd7\x99\xd7\xaa",
    "Content-Type \xd7\x97\xd7\x99\xd7\x99\xd7\x91 \xd7\x9c\xd7\x94\xd7\x99\xd7\x95\xd7\xaa application/x-www-form-urlencoded",
    "CONTENT_LENGTH \xd7\x97\xd7\xa1\xd7\xa8",
    "CONTENT_LENGTH \xd7\x9c\xd7\x90 \xd7\x97\xd7\x95\xd7\xa7\xd7\x99",
    "\xd7\x92\xd7\x95\xd7\xa3 \xd7\x94\xd7\x91\xd7\xa7\xd7\xa9\xd7\x94 \xd7\x90\xd7\x99\xd7\xa0\xd7\x95 UTF-8 \xd7\xaa\xd7\xa7\xd7\x99\xd7\x9f",
    "\xd7\xa8\xd7\xa7 GET \xd7\x95-POST \xd7\xa0\xd7\xaa\xd7\x9e\xd7\x9b\xd7\x99\xd7\x9d",
    "\xd7\x98\xd7\xa2\xd7\x99\xd7\xa0\xd7\xaa \xd7\xaa\xd7\xa6\xd7\x95\xd7\xa8\xd7\xaa \xd7\xa8\xd7\xa9\xd7\x99\xd7\x9e\xd7\xaa \xd7\x94\xd7\x94\xd7\x99\xd7\xaa\xd7\xa8\xd7\x99\xd7\x9d \xd7\xa0\xd7\x9b\xd7\xa9\xd7\x9c\xd7\x94",
    "\xd7\x94\xd7\x91\xd7\xa7\xd7\xa9\xd7\x94 \xd7\x97\xd7\x95\xd7\xa8\xd7\x92\xd7\xaa \xd7\x9e\xd7\x9e\xd7\x92\xd7\x91\xd7\x9c\xd7\x95\xd7\xaa \xd7\x94\xd7\x92\xd7\x95\xd7\x93\xd7\x9c"
};

static const LocalizedStrings GA = {
    "Ceart go leor",
    "403 Toirmiscthe",
    "Am rite an iarratais",
    "REQUEST_METHOD ar iarraidh",
    "Cosan cumra\xc3\xadochta neamhbhail\xc3\xad",
    "Earr\xc3\xa1id inmhe\xc3\xa1nach freastala\xc3\xad",
    "N\xc3\xad m\xc3\xb3r don Content-Type a bheith ina application/x-www-form-urlencoded",
    "CONTENT_LENGTH ar iarraidh",
    "CONTENT_LENGTH neamhbhail\xc3\xad",
    "N\xc3\xadl corp an iarratais ina UTF-8 bail\xc3\xad",
    "N\xc3\xad dtaca\xc3\xadtear ach le GET agus POST",
    "Theip ar lucht\xc3\xba cumra\xc3\xadochta an liosta ceadaithe",
    "T\xc3\xa1 an t-iarratas thar theorainneacha m\xc3\xa9ide"
};

/* ── Language lookup table ────────────────────────────────────────────── */

typedef struct {
    const char           *tag;     /* BCP 47 tag (lowercased) */
    const LocalizedStrings *strings;
} LangEntry;

/*
 * Full tags must appear before their primary subtags so that a specific
 * variety (e.g. "zh-hk") is matched before the generic one ("zh").
 */
static const LangEntry LANG_TABLE[] = {
    /* Traditional Chinese variants → zh-HK strings */
    { "zh-hk",  &ZH_HK },
    { "zh-tw",  &ZH_HK },
    { "zh-mo",  &ZH_HK },
    /* Simplified Chinese / generic zh → ZH strings */
    { "zh",     &ZH    },
    { "zh-cn",  &ZH    },
    { "zh-sg",  &ZH    },
    { "zh-my",  &ZH    },
    /* Norwegian varieties */
    { "nb",     &NO    },
    { "nn",     &NO    },
    /* All other primary subtags */
    { "en",     &EN    },
    { "de",     &DE    },
    { "es",     &ES    },
    { "fr",     &FR    },
    { "pt",     &PT    },
    { "it",     &IT    },
    { "ko",     &KO    },
    { "hi",     &HI    },
    { "ru",     &RU    },
    { "ar",     &AR    },
    { "sw",     &SW    },
    { "ja",     &JA    },
    { "ht",     &HT    },
    { "haw",    &HAW   },
    { "sm",     &SM    },
    { "mi",     &MI    },
    { "af",     &AF    },
    { "nl",     &NL    },
    { "ha",     &HA    },
    { "am",     &AM    },
    { "yo",     &YO    },
    { "bn",     &BN    },
    { "et",     &ET    },
    { "fi",     &FI    },
    { "sv",     &SV    },
    { "no",     &NO    },
    { "uk",     &UK    },
    { "th",     &TH    },
    { "id",     &ID    },
    { "tl",     &TL    },
    { "ms",     &MS    },
    { "jv",     &JV    },
    { "el",     &EL    },
    { "la",     &LA    },
    { "he",     &HE    },
    { "ga",     &GA    },
};

#define LANG_TABLE_COUNT (sizeof(LANG_TABLE) / sizeof(LANG_TABLE[0]))

/* ── Accept-Language parsing ──────────────────────────────────────────── */

/*
 * Look up a language tag (lowercased, NUL-terminated, length tag_len) in
 * LANG_TABLE.  Returns the matching LocalizedStrings pointer, or NULL.
 *
 * Two passes:
 *   1. Exact match on the full tag (e.g. "zh-hk").
 *   2. If the tag contains a '-' subtag, match only the primary subtag
 *      (e.g. "zh" for "zh-sg").
 */
static const LocalizedStrings *
find_strings_for_tag(const char *tag, size_t tag_len)
{
    size_t i;

    /* Pass 1: full tag. */
    for (i = 0; i < LANG_TABLE_COUNT; i++) {
        size_t entry_len = strlen(LANG_TABLE[i].tag);
        if (entry_len == tag_len &&
            strncmp(LANG_TABLE[i].tag, tag, tag_len) == 0)
            return LANG_TABLE[i].strings;
    }

    /* Pass 2: primary subtag only. */
    const char *dash = (const char *)memchr(tag, '-', tag_len);
    if (dash) {
        size_t primary_len = (size_t)(dash - tag);
        for (i = 0; i < LANG_TABLE_COUNT; i++) {
            size_t entry_len = strlen(LANG_TABLE[i].tag);
            if (entry_len == primary_len &&
                strncmp(LANG_TABLE[i].tag, tag, primary_len) == 0)
                return LANG_TABLE[i].strings;
        }
    }

    return NULL;
}

/*
 * Parse one comma-separated Accept-Language token into a lowercased,
 * NUL-terminated language tag (stripping the optional ";q=..." quality
 * value and leading/trailing ASCII whitespace).
 *
 * src       : pointer to the start of the token in the header value.
 * src_len   : byte length of the token.
 * buf       : caller-supplied buffer to write the result into.
 * buf_size  : size of buf (must be > 0).
 *
 * Returns the length of the tag written to buf (0 means nothing useful).
 */
static size_t
normalise_tag(const char *src, size_t src_len, char *buf, size_t buf_size)
{
    /* Strip leading whitespace. */
    while (src_len > 0 && (unsigned char)src[0] <= ' ') {
        src++;
        src_len--;
    }
    /* Strip trailing whitespace. */
    while (src_len > 0 && (unsigned char)src[src_len - 1] <= ' ')
        src_len--;

    /* Truncate at ';' (quality value). */
    size_t i;
    for (i = 0; i < src_len; i++) {
        if (src[i] == ';') {
            src_len = i;
            break;
        }
    }

    /* Strip trailing whitespace again after removing quality. */
    while (src_len > 0 && (unsigned char)src[src_len - 1] <= ' ')
        src_len--;

    if (src_len == 0) return 0;

    /* Copy and lowercase (ASCII only — BCP 47 tags are ASCII). */
    size_t out_len = src_len < buf_size - 1 ? src_len : buf_size - 1;
    for (i = 0; i < out_len; i++)
        buf[i] = (char)tolower((unsigned char)src[i]);
    buf[out_len] = '\0';

    return out_len;
}

/* ── Public API ───────────────────────────────────────────────────────── */

const LocalizedStrings *
get_localized_strings(const char *accept_language)
{
    if (!accept_language || accept_language[0] == '\0')
        return &EN;

    const char *p = accept_language;
    char tag_buf[32]; /* BCP 47 tags are well under 32 chars */

    while (*p != '\0') {
        /* Find the end of this comma-separated token. */
        const char *comma = strchr(p, ',');
        size_t token_len  = comma ? (size_t)(comma - p) : strlen(p);

        size_t tag_len = normalise_tag(p, token_len, tag_buf, sizeof(tag_buf));
        if (tag_len > 0) {
            const LocalizedStrings *ls = find_strings_for_tag(tag_buf, tag_len);
            if (ls) return ls;
        }

        if (!comma) break;
        p = comma + 1;
    }

    return &EN; /* fallback */
}
