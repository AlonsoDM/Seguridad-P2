#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

import nbconvert
from nbconvert.writers import FilesWriter


def convert_html(input_path, output_dir):
    exporter = nbconvert.HTMLExporter()
    exporter.embed_images = True
    body, _resources = exporter.from_filename(str(input_path))
    output_path = output_dir / f"{input_path.stem}.html"
    output_path.write_text(body, encoding="utf-8")
    return output_path


def convert_markdown(input_path, output_dir, storage_mode):
    exporter = nbconvert.MarkdownExporter()
    body, resources = exporter.from_filename(str(input_path))
    output_path = output_dir / f"{input_path.stem}.md"

    if storage_mode == "saved_assets":
        writer = FilesWriter(build_directory=str(output_dir))
        written_path = writer.write(body, resources, notebook_name=input_path.stem)
        return Path(written_path)

    output_path.write_text(body, encoding="utf-8")
    return output_path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--format", required=True, choices=["html", "markdown"])
    parser.add_argument("--storage-mode", required=True)
    args = parser.parse_args()

    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        if args.format == "html":
            output_path = convert_html(input_path, output_dir)
        else:
            output_path = convert_markdown(input_path, output_dir, args.storage_mode)

        print(
            json.dumps(
                {
                    "status": "ok",
                    "output_path": str(output_path),
                }
            )
        )
        return 0
    except Exception as exc:
        error = {
            "status": "error",
            "message": str(exc),
        }
        print(json.dumps(error))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
