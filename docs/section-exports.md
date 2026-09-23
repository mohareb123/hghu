# تصدير كل الأقسام — TXT + JSON

## الاستخدام

بعد تحميل APK/XAPK أو فحص مشروع، اضغط **↓ كل الأقسام TXT + JSON**.
ينزّل المتصفح ZIP للتقرير المعروض كاملًا، بغض النظر عن البحث والفلاتر والصفحات.
زر JSON القديم ما زال ينزّل التقرير المجمع كما هو. المثال التجريبي قابل للتصدير أيضًا.

«فحص المشروع» يحفظ تلقائيًا:

```text
<project>/runs/<inspection-run>/
  report.json
  sections/
    server.txt
    server.json
    protocol.txt
    protocol.json
    ...
    research_stages/
    index.json
    README.txt
```

افتح مجلد المشروع من الواجهة؛ المسار النسبي الدقيق مسجل في `runs[].sections`
داخل `project.json`. المشاريع القديمة لا تتغير بأثر رجعي؛ أعد فحصها لإنشاء المجلد،
أو نزّل الأقسام لتقريرها القديم من الواجهة.

```powershell
.\ProtoHunter.exe analyze .\game.xapk --profile games -o .\reports\game.json
# game.json + game.sections/؛ التكرار ينشئ game.sections-2/ دون الكتابة فوق المجلد السابق
.\ProtoHunter.exe analyze .\game.apk --sections-dir .\exports\inspection-001
```

عند تمرير `--sections-dir` يجب ألا يكون المجلد موجودًا، ويجب أن يكون ملف التقرير
المجمع خارجه. بدون `-o` أو `--sections-dir` يظل CLI يطبع JSON فقط إلى stdout.
التصدير لا يعيد التحليل ولا يشغّل أي شيفرة مستخرجة. إلغاء فحص المشروع أثناء إنشاء
الأقسام ينظّف مجلد التصدير المؤقت، ولا يترك مجلد أقسام يبدو مكتملًا.

## أسماء ثابتة

كل اسم في الجدول له `.txt` مقروء و`.json` يحفظ القيمة الأصلية للقسم، بما فيها
المسارات والأسطر والإزاحات والثقة والأدلة والحدود الموجودة في التقرير.

| اسم الملفات | القسم الأصلي |
|---|---|
| `server` | servers: مجموعات أدلة المضيفين |
| `endpoint` | endpoints: الروابط والعناوين الفردية |
| `protocol` | protocols: قرائن البروتوكولات |
| `protobuf` | protobuf: أدلة Protobuf/gRPC |
| `smali` | smali |
| `native` | native: ELF/Unity/IL2CPP |
| `bundle` | bundles: الحزمة ووحدات Split APK |
| `source` | sources: محتويات/معاينات المصادر المتاحة |
| `research` | research: أدلة البحث |
| `flow` | flow: مراجع الاستدعاء |
| `coverage` | coverage: سجل التغطية |
| `files` | files: سجل الملفات المفحوصة |
| `summary` | summary: الملخص |
| `input` | input: معلومات المدخل |
| `limits` | limits: حدود الفحص |
| `coverage_summary` | coverage_summary |
| `research_plan` | research_plan |
| `warnings` | warnings |
| `limitations` | limitations |
| `metadata` | version + generated_at من التقرير |

مجلد `research_stages` يحتوي أزواجًا منفصلة لـ`login` و`session` و`transport`
و`messages` و`security` و`serialization` و`discovery`. هذه **نسخ مصفاة من research**،
لا أدلة جديدة. الحقول الإضافية المستقبلية تذهب إلى `extra/field-001` وهكذا،
بأسماء آمنة لا تعتمد على مسارات مأخوذة من المدخل.

`index.json` بصيغة `protohunter-sections-v1` يتضمن اسم كل قسم وملفيه، ونوعه
(`original` أو `metadata` أو `derived`) وحقول المصدر (`source_fields`)، وعدد
السجلات وحالة وجوده في التقرير. الأقسام المعروفة الفارغة أو الغائبة تُصدّر أيضًا؛
الغياب موضح بـ`present_in_report: false`. جميع النصوص UTF-8.

## الحدود والخصوصية

التصدير يحتفظ بالحدود والتحذيرات القائمة؛ **لا يحوّل المعاينات المبتورة إلى مصادر
كاملة**، ولا يثبت أن قسمًا فارغًا غير موجود في التطبيق. `protocol` قرائن لا تنفيذ
بروتوكول مسترجع، و`flow` مراجع لا إثبات تدفق تشغيل. مخرجات JADX/Apktool/Il2CppDumper
الأصلية تبقى في مجلدات تشغيلها؛ لا ننسخها كلها داخل ZIP التقرير.

قد تحتوي الملفات عناوين أو رموزًا أو نصوصًا حساسة؛ راجعها قبل المشاركة.

API: `POST /api/export-sections` مع JSON يحوي `{job: ID}` أو `{project: ID, run: ID}`
للتشغيل المحدد، أو `{report: REPORT}` للمثال/التقرير المحمّل بعد انتهاء المهمة.
مشاريع سطح المكتب والمهام الخاصة تتطلب رمز سطح المكتب وloopback؛ طلبات الأصل
المختلف مرفوضة. حجم طلب JSON البديل الأقصى 64 MiB؛ استخدم مجلد المشروع أو CLI
للتقارير الأكبر. يُجهّز ZIP واحد في المرة بضغط متدفق وملف مؤقت بعد 8 MiB؛
المحاولة المتزامنة الأخرى تتلقى 429، دون حجز خانة التحليل.
