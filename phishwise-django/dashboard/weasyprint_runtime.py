import os
from pathlib import Path


def configure_weasyprint_runtime():
    """Expose Pango/GTK DLLs to WeasyPrint on Windows."""
    if os.name != "nt":
        return
    configured = os.environ.get("WEASYPRINT_DLL_DIRECTORIES", "")
    candidates = [Path(item.strip()) for item in configured.split(os.pathsep) if item.strip()]
    candidates.extend([Path("C:/msys64/mingw64/bin"), Path("C:/msys64/ucrt64/bin")])
    for directory in candidates:
        if directory.is_dir():
            os.environ["PATH"] = f"{directory}{os.pathsep}{os.environ.get('PATH', '')}"
            if hasattr(os, "add_dll_directory"):
                os.add_dll_directory(str(directory))
            return


def write_pdf(template_name, context):
    from django.conf import settings
    from django.template.loader import render_to_string

    configure_weasyprint_runtime()
    from weasyprint import HTML

    html = render_to_string(template_name, context)
    return HTML(string=html, base_url=str(settings.BASE_DIR)).write_pdf()


def font_context():
    from django.conf import settings

    fonts = Path(settings.BASE_DIR) / "assets/fonts/sarabun"
    return {
        "font_regular_uri": (fonts / "Sarabun-Regular.ttf").as_uri(),
        "font_bold_uri": (fonts / "Sarabun-Bold.ttf").as_uri(),
    }
