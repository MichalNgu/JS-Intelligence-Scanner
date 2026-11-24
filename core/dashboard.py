from pathlib import Path


class HtmlDashboardGenerator:
    ASSET_NAMES = ("index.html", "style.css", "app.js")

    def write_assets(self, output_dir: Path) -> list[Path]:
        output_dir = Path(output_dir)
        if not output_dir.is_dir():
            raise FileNotFoundError(f"Report directory does not exist: {output_dir}")
        source_dir = Path(__file__).with_name("report_assets")
        written = []
        for name in self.ASSET_NAMES:
            source = source_dir / name
            destination = output_dir / name
            destination.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
            if not destination.is_file():
                raise OSError(f"Dashboard asset was not written: {destination}")
            written.append(destination)
        return written
