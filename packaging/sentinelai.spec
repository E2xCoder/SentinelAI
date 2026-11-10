# PyInstaller build of SentinelAI: one folder with two programs.
#
#   SentinelAI   windowed program that opens the desktop interface
#   sentinel     command-line program
#
# Run from the repository root:  pyinstaller --noconfirm packaging/sentinelai.spec
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, copy_metadata

ROOT = Path(SPECPATH).parent
datas, binaries, hidden = collect_all("sentinelai")
datas += copy_metadata("sentinelai")
icon = str(ROOT / "packaging" / ("icon.icns" if sys.platform == "darwin" else "icon.ico"))


def analysis(script):
    return Analysis(
        [str(ROOT / script)],
        pathex=[str(ROOT / "src")],
        datas=datas,
        binaries=binaries,
        hiddenimports=hidden,
    )


gui = analysis("src/sentinelai/gui/app.py")
cli = analysis("scripts/pyinstaller_entry.py")

gui_exe = EXE(
    PYZ(gui.pure),
    gui.scripts,
    exclude_binaries=True,
    name="SentinelAI",
    console=False,
    icon=icon,
)
cli_exe = EXE(
    PYZ(cli.pure),
    cli.scripts,
    exclude_binaries=True,
    name="sentinel",
    console=True,
    icon=icon,
)
folder = COLLECT(
    gui_exe,
    gui.binaries,
    gui.datas,
    cli_exe,
    cli.binaries,
    cli.datas,
    name="SentinelAI",
)
if sys.platform == "darwin":
    app = BUNDLE(
        folder,
        name="SentinelAI.app",
        icon=icon,
        bundle_identifier="io.github.e2xcoder.sentinelai",
        info_plist={"CFBundleDisplayName": "SentinelAI", "NSHighResolutionCapable": True},
    )
