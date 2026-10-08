"""Pack a VS Code extension directory into a .vsix without Node/npm.

vs-init runs on customer machines that have VS Code but not necessarily
Node/npm, so rebuilding+reinstalling our companion extension on every
run can't depend on either being present.

Format reverse-engineered from a real `npx @vscode/vsce package` run: a
zip containing [Content_Types].xml, extension.vsixmanifest, and
extension/<extension files>, following the VSIX/OPC conventions VS
Code's installer expects. Only covers the package.json fields our own
bundled extension actually uses -- not a general vsce replacement.
"""
from __future__ import annotations

import json
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

_CONTENT_TYPES = {
    ".js": "application/javascript",
    ".json": "application/json",
    ".html": "text/html",
    ".css": "text/css",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".yml": "application/x-yaml",
    ".yaml": "application/x-yaml",
    ".sh": "application/x-sh",
    ".vsixmanifest": "text/xml",
}

# Only files an actual extension bundle needs ship inside extension/.
_INCLUDE_SUFFIXES = {".js", ".json", ".html", ".css", ".png", ".svg", ".yml", ".yaml", ".sh"}


def _manifest_xml(manifest: dict) -> str:
    categories = ",".join(manifest.get("categories") or ["Other"])
    engine = manifest.get("engines", {}).get("vscode", "*")
    extension_kind = ",".join(manifest.get("extensionKind") or ["workspace"])

    return f"""<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">
  <Metadata>
    <Identity Language="en-US" Id="{escape(manifest["name"])}" Version="{escape(manifest["version"])}" Publisher="{escape(manifest["publisher"])}" />
    <DisplayName>{escape(manifest.get("displayName", manifest["name"]))}</DisplayName>
    <Description xml:space="preserve">{escape(manifest.get("description", ""))}</Description>
    <Tags></Tags>
    <Categories>{escape(categories)}</Categories>
    <GalleryFlags>Public</GalleryFlags>
    <Properties>
      <Property Id="Microsoft.VisualStudio.Code.Engine" Value="{escape(engine)}" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionDependencies" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionPack" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionKind" Value="{escape(extension_kind)}" />
      <Property Id="Microsoft.VisualStudio.Code.LocalizedLanguages" Value="" />
      <Property Id="Microsoft.VisualStudio.Services.GitHubFlavoredMarkdown" Value="true" />
      <Property Id="Microsoft.VisualStudio.Services.Content.Pricing" Value="Free" />
    </Properties>
  </Metadata>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Code"/>
  </Installation>
  <Dependencies/>
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true" />
  </Assets>
</PackageManifest>
"""


def _content_types_xml(extensions: set) -> str:
    defaults = "".join(
        f'<Default Extension="{ext}" ContentType="{_CONTENT_TYPES.get(ext, "application/octet-stream")}"/>'
        for ext in sorted(extensions | {".vsixmanifest"})
    )
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        f"{defaults}</Types>\n"
    )


def build_vsix(ext_dir: Path, out_path: Path) -> None:
    manifest = json.loads((ext_dir / "package.json").read_text(encoding="utf-8"))
    files = [
        p for p in ext_dir.rglob("*")
        if p.is_file() and p.suffix in _INCLUDE_SUFFIXES and not p.name.startswith(".")
    ]
    extensions = {p.suffix for p in files}

    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _content_types_xml(extensions))
        z.writestr("extension.vsixmanifest", _manifest_xml(manifest))
        for path in files:
            z.write(path, f"extension/{path.relative_to(ext_dir).as_posix()}")
