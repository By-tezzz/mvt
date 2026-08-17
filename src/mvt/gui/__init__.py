# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

import click

from .app import create_app


def run_gui():
    @click.command()
    @click.option("--host", default="127.0.0.1", show_default=True, help="Host to bind to.")
    @click.option("--port", default=8080, show_default=True, help="Port to listen on.")
    @click.option("--debug", is_flag=True, default=False, help="Enable Flask debug mode.")
    def _run(host, port, debug):
        """Launch the MVT web GUI."""
        app = create_app()
        print(f"MVT GUI running at http://{host}:{port}/")
        app.run(host=host, port=port, debug=debug, threaded=True)

    _run()
