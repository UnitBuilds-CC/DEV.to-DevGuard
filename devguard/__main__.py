import asyncio
import click
import logging
import uvicorn
from rich.console import Console
from rich.table import Table

from devguard.config import load_config
from devguard.database import init_db, SessionLocal, WhitelistEntry
from devguard.service.worker import DevGuardWorker

console = Console()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("devguard.log", encoding="utf-8")
    ]
)
logger = logging.getLogger("devguard.cli")

@click.group()
def main():
    """DevGuard - Real-time Anti-bot and Moderation System for DEV.to/Forem."""
    pass

@main.command()
def db_init():
    """Initializes the SQLite database tables."""
    console.print("[yellow]Initializing SQLite database...[/yellow]")
    try:
        init_db()
        console.print("[green]Database successfully initialized at data/devguard.db![/green]")
    except Exception as e:
        console.print(f"[red]Failed to initialize database: {e}[/red]")

@main.command()
@click.option("--config-path", default="config.yaml", help="Path to config file")
def run(config_path):
    """Starts the DevGuard Web Dashboard and Background Service scheduler."""
    config = load_config(config_path)
    dashboard_cfg = config.get("dashboard", {})
    
    # Store config in FastAPI app state when run
    # Uvicorn will load the application and run it
    host = dashboard_cfg.get("host", "127.0.0.1")
    port = dashboard_cfg.get("port", 8420)
    
    console.print(f"[bold green]Starting DevGuard Web Service on http://{host}:{port}[/bold green]")
    
    # To pass config to app, we'll store it globally or read it during startup
    # We will import the app dynamically to avoid circular references during init
    from devguard.dashboard.app import app
    app.state_config = config
    
    uvicorn.run(app, host=host, port=port)

@main.command()
@click.argument("username")
@click.option("--config-path", default="config.yaml", help="Path to config file")
def scan(username, config_path):
    """Triggers an immediate manual scan of a specific user."""
    console.print(f"[yellow]Triggering manual scan for user:[/yellow] [bold]{username}[/bold]")
    config = load_config(config_path)
    
    worker = DevGuardWorker(config)
    
    # Run async function in synchronous CLI context
    result = asyncio.run(worker.scan_single_user_now(username))
    
    if "error" in result:
        console.print(f"[red]Scan failed: {result['error']}[/red]")
        return
        
    console.print("\n[bold green]Scan Summary:[/bold green]")
    console.print(f"Username: {result['username']}")
    console.print(f"Risk Score: [cyan]{result['risk_score']:.2%}[/cyan]")
    console.print(f"Verdict: [bold]{result['verdict'].upper()}[/bold]")
    console.print(f"Action Taken: [bold]{str(result['action_taken']).upper()}[/bold]")
    
    if result["flags"]:
        console.print("\n[bold yellow]Triggered Indicators:[/bold yellow]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Detector")
        table.add_column("Rule Name")
        table.add_column("Severity")
        table.add_column("Description")
        
        for flag in result["flags"]:
            table.add_row(
                flag["detector"],
                flag["rule_name"],
                f"{flag['severity']:.2f}",
                flag["description"]
            )
        console.print(table)
    else:
        console.print("\n[green]No flags triggered. User is clean.[/green]")

@click.group(name="whitelist")
def whitelist_group():
    """Manage Whitelist entries."""
    pass

@whitelist_group.command(name="add")
@click.argument("username")
@click.option("--reason", default="Manual Whitelist Add", help="Reason for whitelisting")
def whitelist_add(username, reason):
    """Add a user to the whitelist."""
    db = SessionLocal()
    try:
        # Check if already whitelisted
        existing = db.query(WhitelistEntry).filter(WhitelistEntry.username == username).first()
        if existing:
            console.print(f"[yellow]User '{username}' is already whitelisted.[/yellow]")
            return
            
        entry = WhitelistEntry(username=username, reason=reason)
        db.add(entry)
        db.commit()
        console.print(f"[green]Successfully whitelisted user '{username}'![/green]")
    except Exception as e:
        console.print(f"[red]Failed to whitelist: {e}[/red]")
    finally:
        db.close()

@whitelist_group.command(name="remove")
@click.argument("username")
def whitelist_remove(username):
    """Remove a user from the whitelist."""
    db = SessionLocal()
    try:
        entry = db.query(WhitelistEntry).filter(WhitelistEntry.username == username).first()
        if not entry:
            console.print(f"[yellow]User '{username}' is not in the whitelist.[/yellow]")
            return
            
        db.delete(entry)
        db.commit()
        console.print(f"[green]Successfully removed user '{username}' from whitelist.[/green]")
    except Exception as e:
        console.print(f"[red]Failed to remove whitelist entry: {e}[/red]")
    finally:
        db.close()

@whitelist_group.command(name="list")
def whitelist_list():
    """List all whitelisted users."""
    db = SessionLocal()
    try:
        entries = db.query(WhitelistEntry).all()
        if not entries:
            console.print("[yellow]Whitelist is empty.[/yellow]")
            return
            
        table = Table(show_header=True, header_style="bold blue")
        table.add_column("Username")
        table.add_column("Reason")
        table.add_column("Added At")
        
        for e in entries:
            table.add_row(e.username, e.reason, e.added_at.strftime("%Y-%m-%d %H:%M:%S"))
        console.print(table)
    except Exception as e:
        console.print(f"[red]Failed to list whitelist: {e}[/red]")
    finally:
        db.close()

main.add_command(whitelist_group)

if __name__ == "__main__":
    main()
