import json
from typing import Callable, Iterable, Iterator, List

import click

from ggshield.core.constants import MAX_WORKERS
from ggshield.core.text_utils import create_progress_bar
from ggshield.core.utils import ScanContext, ScanMode, handle_exception
from ggshield.output import OutputHandler
from ggshield.scan import File, ScanCollection
from ggshield.scan.scannable import Scanner


def generate_files_from_docsets(path: str, verbose: bool = False) -> Iterator[File]:
    with open(path, "r") as file:
        for line in file:
            obj = json.loads(line)
            documents = obj["documents"]
            for document in documents:
                if verbose:
                    click.echo(f"  * {document['id']}", err=True)
                yield File(document["content"], document["id"])


def create_scans_from_docset_paths(
    scanner: Scanner,
    paths: Iterable[str],
    progress_callback: Callable[[], None],
    verbose: bool = False,
) -> List[ScanCollection]:
    scans: List[ScanCollection] = []

    for path in paths:
        if verbose:
            click.echo(f"- {click.format_filename(path)}", err=True)

        files = generate_files_from_docsets(path, verbose)
        results = scanner.scan(
            files, scan_threads=MAX_WORKERS, progress_callback=lambda **x: None
        )
        scans.append(ScanCollection(id=path, type="docset", results=results))
        progress_callback()

    return scans


@click.command()
@click.argument(
    "paths", nargs=-1, type=click.Path(exists=True, resolve_path=True), required=True
)
@click.pass_context
def docset_cmd(ctx: click.Context, paths: List[str]) -> int:  # pragma: no cover
    """
    scan docset JSONL files.
    """
    config = ctx.obj["config"]
    output_handler: OutputHandler = ctx.obj["output_handler"]
    try:
        with create_progress_bar(doc_type="files") as progress:
            task_scan = progress.add_task(
                "[green]Scanning content...", total=len(paths)
            )

            scan_context = ScanContext(
                scan_mode=ScanMode.PATH,
                command_path=ctx.command_path,
            )
            scanner = Scanner(
                client=ctx.obj["client"],
                cache=ctx.obj["cache"],
                matches_ignore=config.secret.ignored_matches,
                scan_context=scan_context,
                ignored_detectors=config.secret.ignored_detectors,
            )

            scans = create_scans_from_docset_paths(
                scanner=scanner,
                paths=paths,
                verbose=config.verbose,
                progress_callback=lambda: progress.update(task_scan),
            )
            return output_handler.process_scan(
                ScanCollection(id=scan_context.command_id, type="docset", scans=scans)
            )
    except Exception as error:
        return handle_exception(error, config.verbose)
