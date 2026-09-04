{ lib, ... }@ctx:

let
  h = import ../helpers/bundle-artifacts.nix ctx;
  splitCaseSources = map
    (relativePath: builtins.readFile (ctx.flakeRoot + relativePath)) [
      "/tests/unit/nix/helpers/bundle-artifacts.nix"
      "/tests/unit/nix/cases/bundle-artifacts-compiler.nix"
      "/tests/unit/nix/cases/bundle-artifacts-digest.nix"
      "/tests/unit/nix/cases/bundle-artifacts-envelope.nix"
    ];
  forbiddenRealizationFragments = [
      ("builtins.fromJSON (builtins.readFile " + "digestBundle.path")
      ("builtins.readFile " + "hostileCompilerBuild")
      ("builtins.readFile " + "acceptedShimBuild")
      ("builtins.readFile " + "compilerBuild")
      ("toString " + "firstBundle.path")
      ("toString " + "secondBundle.path")
      ("pkgs." + "runCommand")
      ("nativeBuildInputs = [ " + "compilerPackage ]")
  ];
  noRealCompilerDerivationReads = lib.all
    (source:
      lib.all
        (fragment: !(lib.hasInfix fragment source))
        forbiddenRealizationFragments)
    splitCaseSources;
in
{
  "bundle-artifacts/phase2-compiler-is-the-build-validator" = {
    expr = {
      fakeCompilerSelected = h.compilerSelected;
      fakeCompilerCommand = h.compilerCommand;
      noRealCompilerDerivationReads = noRealCompilerDerivationReads;
      sourceUsesCompiler =
        lib.hasInfix "d2b-resource-compiler compile" h.compilerSource
        && !(lib.hasInfix "python3 -" h.compilerSource);
      sourceWiresCompilerInput =
        lib.hasInfix ("compilerInput = " + "pkgs." + "runCommand") h.compilerSource
        && lib.hasInfix "compilerClosureInputs =" h.compilerSource
        && lib.hasInfix
          "passAsFile = [ \"compilerInputJson\" \"compilerClosureInputPaths\" ]"
          h.compilerSource
        && lib.hasInfix
          ("nativeBuildInputs = [ " + "compilerPackage ]")
          h.compilerSource;
      sourceUsesFramedDigest =
        lib.hasInfix "framed_canonical_digest" h.compilerMainSource;
      commandReceivesExpectedHash =
        lib.hasInfix "expectedContentHash = data.contentHash" h.compilerSource;
    };
    expected = {
      fakeCompilerSelected = true;
      fakeCompilerCommand = "d2b-resource-compiler";
      noRealCompilerDerivationReads = true;
      sourceUsesCompiler = true;
      sourceWiresCompilerInput = true;
      sourceUsesFramedDigest = true;
      commandReceivesExpectedHash = true;
    };
  };

  "bundle-artifacts/phase2-input-does-not-inline-duplicate-large-payloads" = {
    expr = {
      usesPrivatePathRefs =
        lib.hasInfix "artifactCatalogPath =" h.compilerSource
        && lib.hasInfix "schemaRoot =" h.compilerSource;
      noCatalogPayloadCopy = !(lib.hasInfix "catalogData" h.compilerSource);
      noSchemaPayloadCopy = !(lib.hasInfix "schemaRootData" h.compilerSource);
      noPythonCompiler = !(lib.hasInfix "python3 -" h.compilerSource);
      fakeCompilerIsEvalOnly = h.compilerSelected;
    };
    expected = {
      usesPrivatePathRefs = true;
      noCatalogPayloadCopy = true;
      noSchemaPayloadCopy = true;
      noPythonCompiler = true;
      fakeCompilerIsEvalOnly = true;
    };
  };
}
