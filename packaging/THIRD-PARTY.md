# Third-party distribution notices and corresponding source

ProtoHunter's own code is MIT licensed. This distribution is an aggregate of
separate programs; the bundled third-party programs retain their own licenses.
The upstream projects do not endorse ProtoHunter. No upstream executable is
represented as an original ProtoHunter decompiler.

- **JADX 1.5.3**: Apache-2.0. Full official distribution is preserved in tools/jadx;
  additional LICENSE/NOTICE copies are in licenses/. Source:
  https://github.com/skylot/jadx/tree/v1.5.3
- **Apktool 2.12.1**: Apache-2.0. Official unmodified shaded JAR in tools/apktool.jar,
  including its embedded resources/notices. License in licenses/.
  Source: https://github.com/iBotPeaches/Apktool/tree/v2.12.1
- **Il2CppDumper**: MIT, Perfare and contributors. Built from unchanged source
  commit 4741d46ba9cd6159c5d853eb9d6fc48b4bfa2b1a targeting .NET 8 win-x64,
  self-contained, without trimming. The shipped configuration changes only
  RequireAnyKey to false for non-interactive use. Original source archive and
  assembly instructions are in the accompanying ProtoHunter-third-party-sources
  artifact. Source: https://github.com/Perfare/Il2CppDumper
- **Mono.Cecil 0.11.4**: MIT; its license is in licenses/.
  https://github.com/jbevain/cecil/tree/0.11.4
- **Microsoft .NET runtime 8.0.31**: MIT and third-party components; LICENSE and
  THIRD-PARTY-NOTICES are in licenses/. The app-local runtime is in tools/il2cpp.
  https://github.com/dotnet/runtime/tree/v8.0.31
- **Eclipse Temurin/OpenJDK 21.0.12.1+1 JRE**: GPLv2 with the Classpath Exception,
  plus applicable third-party licenses. All original legal files remain in
  tools/java/legal and the upstream distribution. The unchanged corresponding
  source release, OpenJDK21U-jdk-sources_21.0.12.1_1.tar.gz, is provided through
  the **ProtoHunter-third-party-sources** artifact on the SAME Actions run as
  the binary bundle, with the same retention period. It is not needed to run.
  Exact official source URL and SHA-256 are recorded in bundle-provenance.json.
  https://github.com/adoptium/temurin21-binaries/releases/tag/jdk-21.0.12.1%2B1

The source artifact and binary bundle must remain available together. Anyone
redistributing this bundle must preserve notices and make the corresponding
GPL-covered sources available as required by the applicable license. Do not
redistribute the binary bundle while discarding the matching source offer.
Build prerequisites/instructions: repository packaging/bundle_windows.py,
packaging/bundle.lock.json and the Windows workflow. These are not a commercial
warranty or a legal opinion about a different downstream distribution.

All engine/runtime downloads are version-pinned and SHA-256 verified before
packaging. The bundle includes a per-file manifest; checksums are integrity
checks, not a publisher code-signing certificate. Windows APIs/browser remain
OS requirements. Android SDK signing tools are NOT included in this bundle.
