# ProtoHunter

**مساحة محلية لتحليل حزم ألعاب Android وNative/IL2CPP وProtobuf وSmali — v0.7.0.**

أداة أولية عملية (MVP) مستوحاة من أسلوب استكشاف الملفات في [JADX](https://github.com/skylot/jadx)، وليست بديلًا كاملًا عنه أو محرك decompiler جديدًا. تجمع مؤشرات الاتصال وتربطها بالدليل، وتستخدم JADX وApktool اختياريًا لفك التطبيق.

- واجهة ويب عربية RTL، تعمل دون خطوط أو خدمات خارجية.
- CLI للتكامل مع سير عمل التحليل.
- لا يتم تشغيل التطبيق، أو الاتصال بالعناوين المستخرجة، أو إرسال الملفات لخدمات تحليل خارجية.
- Python **3.10+**، دون مكتبات تشغيل إلزامية من طرف ثالث.

## الحزمة الكاملة الجاهزة — جديد في 0.7

تحميل **ProtoHunter-Complete-windows-x64** يضم الآن المحركات الحقيقية: JADX 1.5.3، Apktool 2.12.1، وIl2CppDumper مع .NET 8 محلية، بالإضافة إلى Temurin Java 21. لا تثبيت Java/.NET ولا PATH ولا تنزيل عند أول تشغيل؛ فك الضغط وشغّل EXE مع إبقاء مجلد `tools` بجواره.

هي حزمة portable موحّدة وليست إعادة كتابة المحركات أو ملف EXE منفردًا ضخمًا يعيد استخراج الأدوات كل مرة. التطبيق يكتشف الأدوات المرفقة تلقائيًا ويهاجر مسارات النسخة القديمة. تعديل المسارات ما زال متاحًا كخيار متقدم. [دليل الحزمة](packaging/README-Complete.md) و[تراخيصها ومصادرها](packaging/THIRD-PARTY.md).

- التنزيلات مثبتة الإصدار ومتحقق من SHA-256 قبل البناء: `packaging/bundle.lock.json`.
- `ProtoHunter.exe doctor --verify-bundle` يتحقق من بصمات الملفات بعد فك الضغط.
- CI يشغّل **JADX/Apktool الحقيقيين** على APK صناعي ويبني/يفك/يعيد بناءه، ويختبر بدء Il2CppDumper الحقيقي ورفض metadata غير مدعومة، مع إبعاد Java/dotnet من PATH ونقل الحزمة إلى مسار جديد.
- مصادر OpenJDK المقابلة وIl2CppDumper تُتاح في artifact منفصل **ProtoHunter-third-party-sources** من البناء نفسه، بنفس مدة الاحتفاظ؛ ليست مطلوبة للتشغيل.
- أدوات توقيع Android SDK ومفتاحك ليست ضمن المحركات الثلاثة المرفقة. لا ضمان لفك كل حماية أو استرجاع أجسام C# أو نجاح تشغيل APK معدل.

البناء الكامل على Windows: `packaging/build-windows.ps1` ثم `python packaging/bundle_windows.py` ثم `python packaging/smoke_bundle.py dist/ProtoHunter-Complete`، مع .NET SDK 8.0.425 في بيئة البناء فقط. السكربت الأول ينتج EXE منفردًا؛ الثاني يجهّز التوزيعة الكاملة. لا تحفظ ملفات الأدوات أو المصادر الكبيرة في Git.

## استوديو JADX + Apktool + Il2CppDumper — جديد في 0.6

أُضيفت مساحة **مشاريع دائمة**: حفظ أصل APK/XAPK وبصمته، اختيار split، تشغيل المحركات الثلاث، عرض وبحث المخرجات، تحرير Smali/XML مع diff ونسخ احتياطية واستعادة، إعادة بناء APK، ثم محاذاة وتوقيع بمفتاحك باستخدام أدوات Android SDK والتحقق منه. نتائج الفحص تجمع المشاهد المشتقة مع مصدر Apktool الحالي، مع بيان اختلافها وحدودها.

**هذا دمج عبر محركات خارجية، لا تضمين كامل للأدوات في EXE ولا استرجاع لأجسام دوال C# أو تحويل Java المعروضة إلى مشروع قابل للبناء.** لا إعادة بناء Unity/native أو تثبيت ADB أو دمج splits في APK شامل. اقرأ [دليل المشاريع والقيود والاختبارات](docs/workspaces.md) قبل الاستخدام.

في EXE: إعداد المحركات ← مشروع جديد ← اختيار وحدة APK ← فك ← عرض الفرق/حفظ ← بناء ← توقيع اختياري ← فتح مجلد المشروع. أدوات التطوير والتعديل محلية فقط ولا تظهر كعمليات فعالة في المعاينة العامة.

## تحسين تحميل APK/XAPK وApktool JAR — جديد في 0.5

- **فتح مباشر من الجهاز بدون رفع** في EXE على Windows؛ لا تُنسخ الحزمة عبر المتصفح.
- تقدم رفع منفصل عن تقدم الفحص، مهام خلفية، وإلغاء مع تنظيف الملفات المؤقتة.
- قراءة أعضاء ZIP الصغيرة في الذاكرة بدل إنشاء ملف مؤقت لكل عضو، وتقليل حساب البصمات المكرر.
- وضع سريع يتخطى امتدادات الوسائط والخطوط وبعض textures ويسجل التخطي؛ وضع عميق يحتفظ بنطاق الفحص السابق. الفحص السريع مع Apktool يستخدم `-r` لتجنب فك الموارد؛ فحص سلاسل الموارد المباشر مستمر.
- اختيار **apktool.jar وjava.exe** من إعدادات الواجهة وفحص تشغيلهما، دون ملف BAT أو PATH. Java Runtime لا يزال مطلوبًا وغير مضمّن.

راجع [خطوات Windows](packaging/README-Windows.md). مثال CLI:

```powershell
.\ProtoHunter.exe analyze .\game.xapk --profile games --scan-mode fast --decode apktool --apktool-jar "C:\Tools\apktool.jar" --java "C:\Java\bin\java.exe" -o .\reports\game.json
```

الواجهة تبدأ سريعًا وبلا decoder؛ CLI يبدأ عميقًا. فك Smali يظل اختياريًا وقد يستغرق دقائق. اختبار صناعي صغير تحسن من ~1.14s إلى ~0.55s عميق/~0.08s سريع، وليس قياسًا لأداء لعبة حقيقية.

API الواجهة: `POST /api/jobs?name=game.xapk&profile=games&scan_mode=fast` ببيانات ثنائية يعيد `job_id`؛ ثم `GET /api/jobs/{id}` للحالة، `/result` للتقرير، و`POST /api/jobs/{id}/cancel` للإلغاء. يحتفظ الخادم بآخر مهمتين فقط، مع انتهاء صلاحية التقرير بعد ساعة. `/api/analyze` المتزامن باقٍ للتوافق.

إعداد الأدوات واختيار الملفات المحلية غير متاحين في المعاينة العامة. لتفعيلهما من المصدر استخدم `serve --host 127.0.0.1 --desktop-tools --allow-decoders`؛ يتطلب API الإعداد رمزًا خاصًا ونطاق loopback صحيحًا. الخادم ليس خدمة عامة موثّقة الهوية؛ لا تعرضه لشبكة غير موثوقة.

## نسخة Windows EXE — جديد في 0.4

ملف **`ProtoHunter.exe` portable** لـWindows 10/11 x64، دون تثبيت Python أو Node.js. النقر المزدوج يبدأ الخادم على loopback ومنفذ حر، ويفتح الواجهة في المتصفح. أبقِ نافذة البرنامج مفتوحة أثناء التحليل، وأغلقها أو اضغط Ctrl+C لإيقافه.

الـEXE يدعم نفس أوامر CLI:

```powershell
.\ProtoHunter.exe analyze .\game.xapk --profile games -o .\reports\game.json
.\ProtoHunter.exe doctor
```

في EXE المنفرد/نسخة المصدر تحتاج إعداد الأدوات؛ **الحزمة الكاملة 0.7 تتضمن المحركات وبيئات التشغيل**. الملف غير موقّع رقميًا. تعليمات التشغيل والتحقق من SHA-256 في [README Windows](packaging/README-Windows.md).

### بناء EXE من المصدر

البناء يتم **على Windows x64** باستخدام Python 3.12 وJDK 17 مع ضبط `JAVA_HOME` لاختبار ربط JAR فقط؛ PyInstaller لا يحوّل بناء Linux إلى Windows EXE.

```powershell
.\packaging\build-windows.ps1
```

النتيجة في `dist/ProtoHunter.exe` ومعها `SHA256SUMS.txt`. السكربت ينشئ بيئة بناء مستقلة، ويشغّل الاختبارات، ثم يبني نسخة one-file ويختبر الملف التنفيذي نفسه عبر CLI وخادم الواجهة.

يوجد workflow باسم **Windows EXE** يبني على `windows-2022` ويرفع artifact باسم `ProtoHunter-Complete-windows-x64`. يتضمن EXE وتعليمات التشغيل والبصمة والترخيص. ملفات البناء التنفيذية ليست جزءًا من Git؛ الـartifact محفوظ لمدة 30 يومًا، ويمكن إعادة البناء من المصدر.

## خطة Login → Session → Game — جديد في 0.3

أُضيفت [خطة بحث مفصلة](docs/research-plan.md) تغطي الأسماء المحددة من المستخدم: `CSMajorLoginReq/Resp`، `http.proto`، `N2/c.smali`، `LP2/c.smali`، `VodkaConfig`، مصادر `appKey/appSecret/serverId`، حقول الجلسة و`GetLoginData`، ملفات TCP وعائلات رسائل اللعبة.

الواجهة تعرض checklist، مراجع استدعاءات Smali، فلتر العناوين ذات الصلة، **سجل تغطية مستقل**. لا تُعامل القرائن النصية كدليل تنفيذ، ولا تُعرض قراءة البايتات كأنها فهم للمنطق بنسبة 100%.

```bash
python -m protohunter analyze game.xapk --profile games \
  --decode both -o reports/research.json
```

بدون JADX/Apktool احذف `--decode both` أو حلّل مجلدًا مفكوكًا. انظر الوثيقة لحدود الفهرسة، الخصوصية، ودلالة كل نوع من الأدلة.

## وضع الألعاب والحزم المقسّمة — جديد في 0.2

التطوير مناسب لفحص ملفات ألعاب مثل فري فاير **تحليلًا ثابتًا**، لكنه ليس محللًا معتمدًا لبروتوكول اللعبة. لم تصل حزمة فري فاير فعلية للتحقق منها؛ الاختبارات تستخدم حزمًا صناعية. لا توجد سيرفرات أو schemas جاهزة/مفترضة لفري فاير ضمن الأداة.

- **XAPK / APKS / ZIP وSplit APK:** تحليل APK المتداخلة والموارد، مع مسار دليل مثل `config.arm64.apk!lib/arm64-v8a/libil2cpp.so`. يمكنك أيضًا تحليل مجلد يجمع `base.apk` وملفات splits وOBB.
- **ELF 32/64-bit:** المعمارية، ترتيب البايتات، الأقسام، `DT_NEEDED`، وعينة الرموز المستوردة/المعرّفة؛ إبراز رموز الشبكات والتشفير وProtobuf. المكتبات منزوع منها section table تُعرّف بالهيدر فقط؛ لا يدّعي القارئ استعادة رموزها.
- **Unity/IL2CPP:** فحص magic/version وجداول السلاسل القياسية لإصدارات metadata 24–31، مع قراءة literal offsets. لا يستعيد C# types أو offsets الحقول/الدوال، ولا يفك metadata المشفّرة أو المعدّلة.
- **Protobuf داخل Native:** نحت مرشحين لـ FileDescriptorProto داخل ELF، عند وجود اسم `.proto` وبنية رسائل/خدمات قابلة للقراءة. النتيجة متوسطة الثقة، وقد تكون ناقصة لأن البيانات الخام ليس لها حد نهاية موحد.
- **Smali:** الدليل النصي يحمل اسم الكلاس والدالة المحيطة، دون ادعاء تتبع تدفق البيانات.
- **تجميع السيرفرات:** دمج الأدلة لنفس المضيف عبر splits وDEX وNative، مع منافذ ومخططات URI وتلميحات دور منخفضة الثقة. وجود مؤشر بروتوكول في نفس الملف **لا يثبت** ارتباطه بهذا السيرفر.
- **موارد أكبر:** وضع `games` يسمح بإدخال 2 GiB وعضو/مكتبة 512 MiB، مع قراءة عبر memory mapping بدل نسخ المكتبة كاملة إلى Python bytes.

```bash
python -m protohunter analyze game.xapk --profile games -o reports/game.json
python -m protohunter analyze ./game-files --profile games --decode both -o reports/full-game.json
python -m protohunter analyze libil2cpp.so --profile games -o reports/native.json
python -m protohunter analyze global-metadata.dat --profile games -o reports/metadata.json
```

الواجهة تبدأ بوضع **ألعاب وحزم كبيرة**؛ CLI وAPI الافتراضيان يظلان `standard`. اختر ملف XAPK/APKS أو ZIP يجمع ملفات اللعبة من الواجهة؛ الإدخال المتعدد المباشر في المتصفح غير مدعوم. للملفات الضخمة أو لتجنّب حدود/مهل proxy المتصفح استخدم CLI محليًا. ملف OBB الذي ليس ZIP يُفحص كسلاسل فقط، دون فك Unity asset bundles.

## التشغيل السريع

من مجلد المشروع:

```bash
python -m protohunter serve
```

افتح `http://127.0.0.1:8765`. اختر ملفًا أو جرّب المثال الصناعي المرفق. المثال يستخدم نطاقات `.invalid` وعنوان IP خاصًا، وليس تطبيقًا أو خدمة حقيقية.

تثبيت أمر CLI اختياريًا:

```bash
python -m venv .venv
source .venv/bin/activate
# Windows: .venv\Scripts\activate
pip install -e .
protohunter serve
```

في بيئة معاينة محمية يمكن استخدام:

```bash
python -m protohunter serve --host 0.0.0.0 --port 8765
```

**الخادم لا يتضمن تسجيل دخول.** لا تعرضه على الإنترنت أو شبكة غير موثوقة. الربط بكل الواجهات مخصص لشبكة موثوقة/معاينة محمية؛ الوضع الافتراضي محلي فقط.

## ما الذي تستخرجه؟

| المجال | الوظيفة | حدود الاستنتاج |
|---|---|---|
| السيرفرات | URLs، المخطط، المضيف والمنفذ، IPv4، نطاقات مرشحة، IPv6 داخل URLs | لا يتم التحقق من نشاط السيرفر؛ النطاقات وIP المجردة قد تكون ثوابت غير شبكية |
| البروتوكولات | مخططات HTTP(S)، WS(S)، gRPC، MQTT، TCP/UDP وغيرها؛ مؤشرات gRPC/Protobuf/HTTP/TLS/QUIC داخل الكود | وجود مكتبة أو نص ليس إثباتًا لاستخدام البروتوكول أثناء التشغيل |
| REST | مسارات تعليقات Retrofit في Java/Kotlin وSmali | المسار النسبي لا يُركّب مع Base URL تلقائيًا |
| DEX | جدول السلاسل مع offset لكل دليل، ودعم ملفات multidex داخل APK | قارئ سلاسل، وليس فك bytecode إلى Java/Smali؛ DEX القياسي little-endian فقط |
| Smali | الكلاسات، الحقول، الدوال واستدعاءات `invoke-*` | فهرسة ساكنة، وليست call graph كاملًا أو data-flow analysis |
| Protobuf | ملفات `.proto` الأصلية ومؤشرات generated code وثوابت `*_FIELD_NUMBER` | المؤشرات وثوابت الأرقام لا تعيد إنشاء schema كاملة |
| Descriptors | `FileDescriptorSet` و`FileDescriptorProto` داخل `.pb/.desc/.protoset/.bin`؛ descriptor كامل داخل سلسلة DEX واحدة | parsing للبنية الأساسية، وليس كل خيارات protobuf أو extensions؛ لا تُجمع الأجزاء المقسمة بين سلاسل DEX |
| gRPC | services، methods، أنواع request/response وstreaming من descriptors؛ مسارات RPC المرشحة من السلاسل | المسارات المكتشفة بالنمط وحده منخفضة الثقة |
| الأدلة | اسم الملف، رقم السطر أو offset ثنائي، مقتطف المصدر، درجة الثقة | درجة الثقة تخص الدليل المستخرج، لا سلامة التطبيق أو نشاط الخادم |

ملفات descriptors تعرض أسماء الحقول وأرقامها وأنواعها، الرسائل المتداخلة، enums وoneofs والخدمات بصيغة JSON. **لا تدّعي الأداة توليد `.proto` كاملة قابلة للترجمة من APK عشوائي، ولا فك payload ثنائي مجهول دون schema.** ملفات `.proto` الموجودة فعلًا محفوظة كنص في التقرير.

يدعم الإدخال ملفات APK/AAB/ZIP/JAR، وDEX، وSmali/Java/Kotlin، وملفات schema/config. يستخرج ASCII وUTF-16LE من الملفات الثنائية مثل native `.so` والموارد. الأرشيفات المتداخلة ذات الامتدادات المعروفة تُفحص تلقائيًا حتى عمق 3 تحت الجذر وبميزانية مشتركة. ملفات AAB تُفحص كأرشيف فقط؛ لا يتم تحويلها إلى APK.

## CLI

```bash
# تقرير JSON إلى ملف
python -m protohunter analyze app.apk -o reports/app.json

# JSON على stdout
python -m protohunter analyze classes.dex > reports/dex.json

# تحليل مجلد مفكوك مسبقًا: Smali/Java/resources/proto
python -m protohunter analyze ./decoded -o reports/decoded.json

# مثال يعمل دون APK أو أدوات خارجية
python -m protohunter analyze protohunter/demo.smali

# فحص توفر المحركات الاختيارية
python -m protohunter doctor
```

خيار `--decode` يقبل `none` (افتراضي)، `auto`، `jadx`، `apktool`، `both`. `auto` يشغّل كل المحركات المتاحة، مع تحذير عن الناقص منها. المحركات تُستخدم مع APK؛ JADX يدعم أيضًا DEX، أما Smali من DEX مستقل فيحتاج أداة منفصلة مثل baksmali ثم تحليل مجلد الناتج.

### ربط JADX وApktool

ثبّت Java والمحركات من مصادرها الرسمية. لأوامر wrappers ضعها على `PATH`، أو استخدم `--apktool-jar` و`--java` للمسارات المباشرة:

- [JADX — installation](https://github.com/skylot/jadx#download)
- [Apktool — installation](https://apktool.org/docs/install/)

```bash
python -m protohunter doctor
python -m protohunter analyze app.apk --decode both -o reports/full.json

# السماح بتشغيل المحركات على الملفات المرفوعة في الواجهة
python -m protohunter serve --allow-decoders
```

JADX يضيف Java، وApktool يضيف Smali والموارد إلى التحليل، بما في ذلك APK الداخلية في الحزم. الحد 8 مدخلات لفك الكود الخارجي لكل تقرير؛ يُشغّل كل محرك مختار على كل مدخل متاح ضمن هذا الحد. يتم استدعاؤهما دون shell، في مجلد مؤقت، بمهلة 180 ثانية لكل محرك. النتائج تُميّز بمقدمة `jadx/` أو `apktool/`. عدم وجود المحركات أو فشلها يعطي تحذيرًا ولا يلغي تحليل السلاسل والأصول.

**المحركات الخارجية ليست sandboxed، وحدود الأرشيف الداخلية لا تحدّ استهلاكها للقرص/الذاكرة.** فعّلها فقط في بيئة معزولة ومحدودة الموارد، خصوصًا عند فحص ملفات غير موثوقة. استخدم نسخًا حديثة منها.

## التقرير والواجهة

- أقسام مستقلة للسيرفرات، البروتوكولات، Protobuf، Smali، تجميع المضيفين، Native/IL2CPP، الحزم، وملفات المصدر.
- البحث حسب القيمة، الملف أو الدليل؛ تصفية حسب الثقة؛ صفحات للنتائج.
- اختيار نتيجة يعرض مصدرها أو الدليل الثنائي، مع نسخ التفاصيل.
- زر **تصدير JSON** يحفظ التقرير كاملًا ضمن حدود التحليل، لا النتائج المرئية فقط.
- عدد «العناوين الفريدة» لا يحتسب تكرار العنوان في المصادر؛ القائمة تحتفظ بكل موضع دليل مختلف.
- حقل `input.sha256` يعرّف الملف الأصلي. تحليل المجلدات لا يولد hash موحدًا.

بنية التقرير:

```text
input        اسم الملف، النوع، الحجم، SHA-256، وضع فك الكود
summary      إحصائيات الملفات، النتائج والوقت
endpoints    value / kind / host / port / scheme / method + الدليل
protocols    مخططات URI ومؤشرات مكتبات الاتصال + الدليل
protobuf     مصادر proto / descriptors / مؤشرات الكود وثوابت الحقول
smali        class / methods / fields / invokes
native       ELF headers / sections / symbols / libraries أو IL2CPP string tables
bundles      أرشيفات وأسماء splits وبيانات manifest.json المعلنة
servers      تجميع الأدلة حسب المضيف؛ ليس call graph
limits       الحدود الفعلية للوضع المختار
research     نتائج خطة Login / session / TCP / message families / crypto
research_plan الأهداف المرصودة وغير المرصودة وحدود البحث
flow         مراجع invoke موجّهة مع caller/callee؛ ليست runtime trace
coverage     سجل طرق الاستخراج والبصمات والأخطاء والملفات المتخطاة
coverage_summary إحصائيات القراءة والحصر دون ضمان فهم كامل
sources      معاينات نصية محدودة الحجم
files        قائمة الملفات المفحوصة وأحجامها
warnings     الملفات المتخطاة، الحدود وأخطاء المحركات
limitations  حدود التفسير والتحليل
```

الملفات المرفوعة ومخرجات المحركات تُحذف بعد انتهاء الطلب. التقرير يبقى في ذاكرة صفحة المتصفح حتى إغلاقها أو استبداله. لا توجد قاعدة بيانات أو telemetry. سجل HTTP قد يحتوي اسم الملف ضمن عنوان الطلب. تقارير JSON **قد تحتوي روابط بها tokens ومقتطفات حساسة**؛ احفظها وشاركها بحذر.

## API المحلي

```bash
curl http://127.0.0.1:8765/api/status
curl -X POST 'http://127.0.0.1:8765/api/analyze?name=app.apk&decode=none&profile=standard' \
  -H 'Content-Type: application/octet-stream' --data-binary @app.apk > report.json
curl -X POST http://127.0.0.1:8765/api/demo \
  -H 'Content-Type: application/octet-stream' --data-binary ''
```

أضف `profile=games` لرفع XAPK والملفات الكبيرة؛ `/api/status` يعرض حدود الوضعين. رفع مباشر للجسم الثنائي، وليس multipart. مطلوب `Content-Length`، ولا يدعم chunked uploads. أسماء الملفات للعرض فقط؛ لا يمكن تحديد مسار ملف على الخادم. لا يسمح الخادم بطلبات متصفح cross-origin، ويقبل مهمة تحليل واحدة في الوقت نفسه (`429` إن كان مشغولًا).

## حدود الموارد والأمان

| الحد | `standard` | `games` |
|---|---:|---:|
| الإدخال/الرفع وعضو أرشيف متداخل | 128 MiB | 2 GiB |
| ملف محتوى مفرد، سواء مباشرة أو داخل أرشيف/مجلد | 16 MiB | 512 MiB |
| إجمالي بيانات المحتوى المفحوصة | 256 MiB | 2 GiB |
| إجمالي البيانات المفكوكة إلى staging، شامل طبقات الحزم | 512 MiB | 4 GiB |
| الملفات المفحوصة / أعضاء الأرشيف عبر الطبقات | 12,000 | 40,000 |
| عمق الأرشيفات تحت الجذر | 3 | 3 |

- تخطي أعضاء ZIP بنسبة ضغط أعلى من **250:1** والمسارات غير الآمنة وsymlinks. كل عضو يُنسخ بالتتابع إلى اسم ثابت في مجلد مؤقت ثم يُحذف؛ **لا يُستخدم اسم العضو كمسار على القرص**. طبقات الحزمة تتشارك ميزانية التفكيك، ولا تُعاد الميزانية لكل APK.
- الملفات النصية فوق 16 MiB تُفحص كسلاسل في وضع الألعاب، دون parsing/معاينة نصية كاملة.
- Memory mapping يقلل نسخ البيانات إلى Python، لكنه ليس حدًا صلبًا للذاكرة/CPU؛ يلزم قرص مؤقت كافٍ للحزمة وأعضائها.
- تجاهل symlinks عند تحليل المجلدات.
- حد أقصى **15,000** نتيجة عامة، و**20,000** نتيجة في خطة البحث بميزانية مستقلة، و**10,000** مرجع invoke موجّه؛ علامات/تحذيرات عند الحدود.
- معاينات المصادر: حتى **500** ملف، **96,000** حرف لكل ملف، و**4 MiB** إجماليًا. معاينة المتصفح تعرض سياق النتيجة أو أول 400 سطر؛ تصدير JSON يحتوي المعاينة المخزنة.
- schema الأصلية: حتى 128,000 حرف؛ حقول `truncated` توضح القص.
- ELF: حتى 4,096 قسمًا، وفحص 100,000 رمز، ومعاينة 512 قسمًا و1,000 رمز و2,000 رمز شبكي لكل مكتبة. قراءة literals من IL2CPP حتى 100,000 سجل بطول أقصى 16,384 بايت لكل literal.
- نحت descriptors من ELF: أول 64 تطابقًا لاسم ملف مرشح، و128 KiB حد نافذة المرشح. بيانات descriptors المباشرة حتى 8 MiB.
- قوائم Smali مخزنة بحد 1,000 دالة و1,000 حقل و500 استدعاء لكل كلاس؛ العدّ الكلي للدوال والحقول محفوظ.
- هذه حدود دفاعية أولية، وليست ضمانًا ضد كل ملفات الاستنزاف. شغّل التحليل غير الموثوق داخل container/VM مع حدود CPU/RAM/disk.

## الاختبارات

```bash
python -m unittest discover -s tests -v
python -m compileall -q protohunter
node --check protohunter/static/app.js  # اختياري، للتحقق من JavaScript
```

الاختبارات تبني APK/DEX/descriptor صناعيًا في مجلدات مؤقتة، وتغطي الاستخراج، offsets، Smali وRetrofit، descriptors، ELF32/64 بترتيبي البايتات، IL2CPP، حزم متعددة الأجزاء، الميزانيات المشتركة، مدخلات تالفة، ZIP غير الآمن، حدود النتائج، HTTP وCLI. لا تشمل التحقق من إخراج JADX/Apktool الحقيقي إن لم يكونا مثبتين.

### اختبار المتصفح الاختياري

بعد تشغيل خادم الواجهة في نافذة أخرى، يتطلب Node.js وPlaywright:

```bash
npm install --no-save --package-lock=false playwright
npx playwright install chromium
node tests/browser.cjs
```

يفحص المثال والبحث والتصفية والتنقل ورفع ملف وتصدير JSON وعرض النص كبيانات لا كـ HTML، وعرض الهاتف، وخطة البحث وسجل التغطية. يمكن تغيير عنوان الخادم بمتغير `PROTOHUNTER_URL`، أو مسار Chromium بمتغير `CHROMIUM_EXECUTABLE_PATH`.

## خريطة الملفات

```text
protohunter/analyzer.py    محرك الاستخراج والتكامل مع المحركات
protohunter/formats.py     قارئ DEX وبنية descriptors ونحت مرشحي Native
protohunter/native.py      قارئ ELF وIL2CPP القياسي
protohunter/research.py    خطة البحث ومراجع Smali وأهمية العناوين
protohunter/coverage.py    سجل القراءة والتخطي وحدود التغطية
protohunter/android.py     string pools في Binary XML/resources
protohunter/cli.py         أوامر CLI
protohunter/web.py         خادم الواجهة وAPI
protohunter/static/        واجهة عربية دون framework
protohunter/demo.smali     مثال اصطناعي آمن
tests/                    اختبارات Python القياسية
```

استخدم الأداة فقط على تطبيقات تملكها أو لديك إذن واضح بتحليلها. المشروع مستقل وغير تابع لفريق JADX أو Apktool.

## License

MIT — see [LICENSE](LICENSE).

اختبار واجهة المهام والإعدادات (يحاكي حوار Windows ومهمة طويلة، ولا يستبدل اختبار API): `node tests/browser-jobs.cjs`.
