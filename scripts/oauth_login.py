#!/usr/bin/env python3
"""OAuth Authorization Code Flow (with PKCE) Test Script for Yoto API.

This script performs an interactive OAuth 2.0 login with PKCE against Auth0:
1. Spawns a temporary local HTTP server listening at http://127.0.0.1:1234.
2. Generates PKCE code verifier and challenge.
3. Generates the authorization URL and attempts to open it in your browser.
4. Waits for the callback containing the authorization code.
5. Exchanges the authorization code for access & refresh tokens.
6. Tests the token against the Yoto API to verify functionality.
"""

import asyncio
import base64
import hashlib
import os
import secrets
import sys
import urllib.parse
import webbrowser
from pathlib import Path

import aiohttp
from aiohttp import web
import datetime
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from yoto_api import YotoClient
from yoto_api.Token import Token
from yoto_api.rest import endpoints

DEFAULT_CLIENT_ID = "oM4qoJlAoEras19K1IkYNpUmgki7vkbA"
DEFAULT_CALLBACK_URL = "http://127.0.0.1:1234"
AUTH_DOMAIN = "https://login.yotoplay.com"
AUTHORIZE_URL = f"{AUTH_DOMAIN}/authorize"
TOKEN_URL = f"{AUTH_DOMAIN}/oauth/token"
AUDIENCE = endpoints.BASE_URL  # "https://api.yotoplay.com"
SCOPES = "openid profile offline_access family:devices:view"

_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
console = Console()


def _generate_pkce_pair() -> tuple[str, str]:
    """Generate (code_verifier, code_challenge) for PKCE."""
    # 32 random bytes -> 43 characters base64url string
    verifier_bytes = secrets.token_bytes(32)
    code_verifier = base64.urlsafe_b64encode(verifier_bytes).decode("utf-8").rstrip("=")
    challenge_bytes = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = (
        base64.urlsafe_b64encode(challenge_bytes).decode("utf-8").rstrip("=")
    )
    return code_verifier, code_challenge


def _build_auth_url(
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    state: str,
) -> str:
    """Build Auth0 /authorize URL."""
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": SCOPES,
        "audience": AUDIENCE,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    return f"{AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"


async def _start_callback_server(
    host: str,
    port: int,
    expected_state: str,
) -> tuple[web.AppRunner, asyncio.Future]:
    """Start local web server to capture OAuth redirect."""
    code_future: asyncio.Future[dict] = asyncio.get_running_loop().create_future()

    async def handle_callback(request: web.Request) -> web.Response:
        params = request.query
        if "error" in params:
            err_msg = params.get(
                "error_description", params.get("error", "Unknown error")
            )
            if not code_future.done():
                code_future.set_exception(RuntimeError(f"OAuth error: {err_msg}"))
            return web.Response(
                text=f"<h1>Login Failed</h1><p>{err_msg}</p>",
                content_type="text/html",
                status=400,
            )

        code = params.get("code")
        state = params.get("state")

        if not code:
            return web.Response(
                text="<h1>Missing code</h1><p>No authorization code received.</p>",
                content_type="text/html",
                status=400,
            )

        if state != expected_state:
            if not code_future.done():
                code_future.set_exception(
                    RuntimeError(
                        f"State mismatch: expected {expected_state}, got {state}"
                    )
                )
            return web.Response(
                text="<h1>Invalid State</h1><p>State verification failed.</p>",
                content_type="text/html",
                status=400,
            )

        if not code_future.done():
            code_future.set_result(dict(params))

        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Yoto Authentication Successful</title>
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                       display: flex; justify-content: center; align-items: center; height: 100vh;
                       margin: 0; background: #f8fafc; color: #1e293b; }
                .card { background: white; padding: 2.5rem; border-radius: 12px;
                        box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); text-align: center; max-width: 400px; }
                h1 { color: #10b981; font-size: 1.75rem; margin-bottom: 0.5rem; }
                p { color: #64748b; line-height: 1.5; }
            </style>
        </head>
        <body>
            <div class="card">
                <h1>Authentication Successful!</h1>
                <p>You can close this window and return to your terminal.</p>
            </div>
        </body>
        </html>
        """
        return web.Response(text=html_content, content_type="text/html")

    app = web.Application()
    # Route root and all subpaths to handle redirects to / or /callback
    app.router.add_get("/", handle_callback)
    app.router.add_get("/{tail:.*}", handle_callback)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    return runner, code_future


async def _exchange_code_for_tokens(
    session: aiohttp.ClientSession,
    client_id: str,
    code: str,
    code_verifier: str,
    redirect_uri: str,
) -> dict:
    """Exchange authorization code + code_verifier for OAuth tokens."""
    data = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "code_verifier": code_verifier,
        "redirect_uri": redirect_uri,
    }
    async with session.post(
        TOKEN_URL,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    ) as response:
        body = await response.json(content_type=None)
        if not response.ok:
            error_desc = body.get(
                "error_description", body.get("error", "Unknown error")
            )
            raise RuntimeError(
                f"Token exchange failed ({response.status}): {error_desc}\nFull response: {body}"
            )
        return body


def _persist_refresh_token(refresh_token: str) -> None:
    """Save or update YOTO_REFRESH_TOKEN in .env."""
    lines = []
    if _ENV_PATH.exists():
        lines = _ENV_PATH.read_text().splitlines()

    new_line = f"YOTO_REFRESH_TOKEN={refresh_token}"
    updated = False
    for i, line in enumerate(lines):
        if line.startswith("YOTO_REFRESH_TOKEN="):
            lines[i] = new_line
            updated = True
            break
    if not updated:
        lines.append(new_line)

    _ENV_PATH.write_text("\n".join(lines) + "\n")
    console.print(f"[green]✓ Saved YOTO_REFRESH_TOKEN to {_ENV_PATH}[/]")


def _persist_access_token(access_token: str) -> None:
    """Save or update YOTO_ACCESS_TOKEN in .env."""
    lines = []
    if _ENV_PATH.exists():
        lines = _ENV_PATH.read_text().splitlines()

    new_line = f"YOTO_ACCESS_TOKEN={access_token}"
    updated = False
    for i, line in enumerate(lines):
        if line.startswith("YOTO_ACCESS_TOKEN="):
            lines[i] = new_line
            updated = True
            break
    if not updated:
        lines.append(new_line)

    _ENV_PATH.write_text("\n".join(lines) + "\n")
    console.print(f"[green]✓ Saved YOTO_ACCESS_TOKEN to {_ENV_PATH}[/]")


async def main() -> int:
    load_dotenv()
    client_id = os.environ.get("YOTO_CLIENT_ID", DEFAULT_CLIENT_ID)
    callback_url = os.environ.get("YOTO_CALLBACK_URL", DEFAULT_CALLBACK_URL)

    parsed_callback = urllib.parse.urlparse(callback_url)
    host = parsed_callback.hostname or "127.0.0.1"
    port = parsed_callback.port or 1234

    console.print(
        Panel.fit(
            f"[bold cyan]Yoto API OAuth 2.0 Login (PKCE)[/]\n"
            f"[dim]Client ID:[/] [yellow]{client_id}[/]\n"
            f"[dim]Callback URL:[/] [yellow]{callback_url}[/]\n"
            f"[dim]Listening on:[/] [yellow]{host}:{port}[/]",
            title="OAuth Setup",
        )
    )

    code_verifier, code_challenge = _generate_pkce_pair()
    state = secrets.token_urlsafe(16)
    auth_url = _build_auth_url(
        client_id=client_id,
        redirect_uri=callback_url,
        code_challenge=code_challenge,
        state=state,
    )

    runner, code_future = await _start_callback_server(host, port, state)

    try:
        console.print(
            f"\n[bold green]Opening browser for login...[/]\n"
            f"If the browser doesn't open automatically, visit this URL:\n\n"
            f"  [underline cyan]{auth_url}[/]\n"
        )
        try:
            webbrowser.open(auth_url)
        except Exception as err:
            console.print(f"[dim]Could not launch browser automatically: {err}[/]")

        console.print("[dim]Waiting for authorization callback (timeout: 120s)...[/]")
        try:
            callback_params = await asyncio.wait_for(code_future, timeout=120)
        except asyncio.TimeoutError:
            console.print("[red]✗ Timed out waiting for browser callback.[/]")
            return 1

        code = callback_params["code"]
        console.print("[green]✓ Authorization code received from callback.[/]")

        console.print("[dim]Exchanging code for tokens with Auth0...[/]")
        async with aiohttp.ClientSession() as session:
            token_response = await _exchange_code_for_tokens(
                session=session,
                client_id=client_id,
                code=code,
                code_verifier=code_verifier,
                redirect_uri=callback_url,
            )

        access_token = token_response.get("access_token")
        refresh_token = token_response.get("refresh_token")
        expires_in = token_response.get("expires_in")
        scope = token_response.get("scope")

        # Display token details
        table = Table(title="OAuth Tokens Received", show_header=True)
        table.add_column("Field", style="bold cyan")
        table.add_column("Value", style="green")
        table.add_row("Token Type", token_response.get("token_type", "Bearer"))
        table.add_row("Expires In", f"{expires_in} seconds")
        table.add_row("Scope", str(scope))
        table.add_row(
            "Access Token",
            f"{access_token}" if access_token else "None",
        )
        table.add_row(
            "Refresh Token",
            f"{refresh_token}" if refresh_token else "None",
        )
        console.print(table)

        if access_token:
            _persist_access_token(access_token)

        if refresh_token:
            _persist_refresh_token(refresh_token)
        else:
            console.print("[yellow]⚠ No refresh token was returned in the response.[/]")

        # Test token with YotoClient
        console.print("\n[bold cyan]Testing token with YotoClient API...[/]")
        async with YotoClient(client_id=client_id) as client:
            client.token = Token(
                access_token=access_token,
                refresh_token=refresh_token,
                scope=scope,
                valid_until=datetime.datetime.now(datetime.UTC)
                + datetime.timedelta(seconds=expires_in),
            )
            await client.update_player_list()
            players = client.players
            console.print(
                f"[green]✓ Successfully authenticated! Found {len(players)} player(s):[/]"
            )
            for p in players.values():
                status = "[green]online[/]" if p.is_online else "[red]offline[/]"
                console.print(
                    f"  • [bold]{p.device.name}[/] ({p.device.device_id}) - {status}"
                )
            client._auth.refresh()

        console.print("\n[bold green]✓ Login flow completed successfully![/]")
        return 0

    except Exception as err:
        console.print(f"\n[red]✗ Error during login flow: {err}[/]")
        return 1
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
