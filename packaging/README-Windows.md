# ProtoHunter 0.4 — Windows x64

## التشغيل

1. استخدم Windows 10 أو Windows 11 بنواة 64-bit.
2. شغّل `ProtoHunter.exe` بالنقر المزدوج؛ لا تحتاج تثبيت Python أو Node.js.
3. تفتح واجهة التحليل في المتصفح. إن لم تُفتح تلقائيًا، انسخ الرابط من نافذة البرنامج.
4. اختر APK/XAPK أو ملفات Smali/Native/Protobuf لبدء التحليل.
5. اترك نافذة البرنامج مفتوحة أثناء العمل. اضغط Ctrl+C أو أغلقها لإيقاف الخادم المحلي.

الاتصال محلي فقط عبر `127.0.0.1`، على منفذ حر يُختار تلقائيًا. لا يوجد أي مطلب لرفع مصدر بوت أو برنامج آخر. إغلاق تبويب المتصفح وحده لا يوقف البرنامج؛ أغلق نافذة البرنامج أيضًا.

النسخة portable وتحتوي Python والواجهة ومحرك التحليل. لا تحتاج صلاحيات Administrator. يفك المشغّل مكونات التشغيل مؤقتًا داخل مجلد Windows Temp؛ الملفات المرفوعة للتحليل مؤقتة كذلك.

## أوامر اختيارية من PowerShell

```powershell
.\ProtoHunter.exe --version
.\ProtoHunter.exe analyze .\game.xapk --profile games -o .\reports\game.json
.\ProtoHunter.exe analyze .\decoded -o .\reports\decoded.json
.\ProtoHunter.exe doctor
```

لفك APK إلى Java وSmali بدل تحليل السلاسل فقط، ثبّت Java وJADX وApktool من مصادرها الرسمية وضعها على PATH، ثم:

```powershell
.\ProtoHunter.exe analyze .\game.apk --decode both -o .\reports\full.json
.\ProtoHunter.exe serve --host 127.0.0.1 --port 8765 --allow-decoders
```

**JADX وApktool وJava غير مضمّنة في EXE.** تشغيل النقر المزدوج لا يفعّل المحركات الخارجية تلقائيًا. موارد APK المشفرة أو المموهة قد لا تكون قابلة للاسترجاع؛ سجل التغطية يوضح حدود الفحص، ولا يوجد ادعاء باستخراج 100% من المنطق.

## التحقق من الملف

```powershell
Get-FileHash .\ProtoHunter.exe -Algorithm SHA256
```

قارن النتيجة مع `SHA256SUMS.txt`. الملف **غير موقّع رقميًا**؛ قد يعرض Windows SmartScreen تحذيرًا للناشر غير المعروف. البصمة تكشف تغيّر الملف، لكنها ليست توقيعًا يثبت هوية ناشره. احصل على الملف من مصدر المشروع الموثوق، ولا تعطّل برامج الحماية.

اختُبر الملف التنفيذي آليًا على عامل Windows لبناء المشروع: التشغيل، CLI، فتح الخادم المحلي، ملفات الواجهة، وAPI التحليل. هذا لا يعني اختباره على كل إصدارات Windows أو كل حزم الألعاب.

لبيئات الاختبار: `PROTOHUNTER_NO_BROWSER=1` يمنع الفتح التلقائي، و`PROTOHUNTER_PORT` يحدد منفذًا بدل الاختيار التلقائي.
