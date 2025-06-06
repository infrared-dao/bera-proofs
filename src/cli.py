#!/usr/bin/env python3
"""
Bera Proofs CLI

Command-line interface for generating Merkle proofs for Berachain beacon state.
Provides interactive and script-friendly commands for proof generation.
"""

import os
import sys
import json
import logging
from typing import Optional, List, Dict, Any
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.syntax import Syntax

# Add src to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.api.proof_service import ProofService, ProofServiceError
from src.api.beacon_client import BeaconAPIClient, BeaconAPIError
from src.api.rest_api import run_server
from src.visualize_merkle import visualize_merkle_proof, demo_visualization
from src.ssz.containers.utils import load_and_process_state
from src.main import generate_validator_proof, generate_balance_proof, generate_proposer_proof

# Configure rich console
console = Console()
logger = logging.getLogger(__name__)


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def print_proof_result(result, proof_type: str, format_output: str = "table"):
    """Print proof results in various formats."""
    if format_output == "json":
        output = {
            "proof": [step.hex() for step in result.proof],
            "root": result.root.hex(),
            "metadata": result.metadata,
            "proof_type": proof_type
        }
        console.print_json(json.dumps(output, indent=2))
        return
    
    # Table format (default)
    table = Table(title=f"{proof_type.title()} Proof Results")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Proof Type", proof_type)
    table.add_row("Root Hash", result.root.hex())
    table.add_row("Proof Steps", str(len(result.proof)))
    
    # Add metadata
    for key, value in result.metadata.items():
        if key == "validator_pubkey" and len(str(value)) > 50:
            value = f"{str(value)[:20]}...{str(value)[-20:]}"
        table.add_row(key.replace("_", " ").title(), str(value))
    
    console.print(table)
    
    if format_output == "detailed":
        console.print("\n[bold cyan]Proof Steps:[/bold cyan]")
        for i, step in enumerate(result.proof):
            console.print(f"  {i:2d}: {step.hex()}")


def format_proof_result(result_dict: Dict[str, Any]) -> str:
    """Format proof result for JSON output."""
    return json.dumps(result_dict, indent=2)


@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option('--api-url', envvar='BEACON_API_URL', help='Beacon API URL')
@click.pass_context
def cli(ctx, verbose: bool, api_url: Optional[str]):
    """
    Bera Proofs CLI - Generate Merkle proofs for Berachain beacon state.
    
    This tool allows you to generate cryptographic proofs for validators,
    balances, and proposers that can be verified against beacon state roots.
    """
    setup_logging(verbose)
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    ctx.obj['api_url'] = api_url


@cli.command()
@click.argument('validator_index', type=int)
@click.option('--json-file', type=str, help='Path to JSON state file')
@click.option('--slot', type=int, help='Slot number for API queries (defaults to head)')
def validator(validator_index: int, json_file: str = None, slot: int = None):
    """
    Generate a validator existence proof.
    
    VALIDATOR_INDEX: Index of the validator to prove
    """
    try:
        if json_file:
            # Load from local JSON file
            state = load_and_process_state(json_file)
            result = generate_validator_proof(state, validator_index)
            
            # Format for JSON output
            output = {
                "proof": [f"0x{step.hex()}" for step in result.proof],
                "root": f"0x{result.root.hex()}",
                "metadata": {
                    **result.metadata,
                    "type": "validator_proof"
                }
            }
        else:
            # Use API
            beacon_client = BeaconAPIClient()
            slot_id = slot if slot is not None else "head"
            
            # Get state data
            state_response = beacon_client.get_state(slot_id)
            
            # Save to temp file and load
            with open("temp_state.json", "w") as f:
                json.dump(state_response["data"], f)
            
            state = load_and_process_state("temp_state.json")
            
            # Get previous cycle data
            try:
                prev_slot = max(0, state.slot - 64)
                prev_state = beacon_client.get_state(prev_slot)
                prev_block = beacon_client.get_block(prev_slot)
                prev_state_root = bytes.fromhex(prev_state["data"]["root"][2:])
                prev_block_root = bytes.fromhex(prev_block["data"]["root"][2:])
            except:
                prev_state_root = None
                prev_block_root = None
            
            result = generate_validator_proof(state, validator_index, prev_state_root, prev_block_root)
            
            # Format for JSON output
            output = {
                "proof": [f"0x{step.hex()}" for step in result.proof],
                "root": f"0x{result.root.hex()}",
                "metadata": {
                    **result.metadata,
                    "type": "validator_proof"
                }
            }
        
        print(format_proof_result(output))
        
    except Exception as e:
        logger.error(f"Error generating validator proof: {e}")
        raise click.ClickException(str(e))


@cli.command()
@click.argument('validator_index', type=int)
@click.option('--json-file', type=str, help='Path to JSON state file')
@click.option('--slot', type=int, help='Slot number for API queries (defaults to head)')
def balance(validator_index: int, json_file: str = None, slot: int = None):
    """
    Generate a validator balance proof.
    
    VALIDATOR_INDEX: Index of the validator balance to prove
    """
    try:
        if json_file:
            # Load from local JSON file
            state = load_and_process_state(json_file)
            result = generate_balance_proof(state, validator_index)
            
            # Format for JSON output
            output = {
                "proof": [f"0x{step.hex()}" for step in result.proof],
                "root": f"0x{result.root.hex()}",
                "metadata": {
                    **result.metadata,
                    "type": "balance_proof"
                }
            }
        else:
            # Use API
            beacon_client = BeaconAPIClient()
            slot_id = slot if slot is not None else "head"
            
            # Get state data
            state_response = beacon_client.get_state(slot_id)
            
            # Save to temp file and load
            with open("temp_state.json", "w") as f:
                json.dump(state_response["data"], f)
            
            state = load_and_process_state("temp_state.json")
            
            # Get previous cycle data
            try:
                prev_slot = max(0, state.slot - 64)
                prev_state = beacon_client.get_state(prev_slot)
                prev_block = beacon_client.get_block(prev_slot)
                prev_state_root = bytes.fromhex(prev_state["data"]["root"][2:])
                prev_block_root = bytes.fromhex(prev_block["data"]["root"][2:])
            except:
                prev_state_root = None
                prev_block_root = None
            
            result = generate_balance_proof(state, validator_index, prev_state_root, prev_block_root)
            
            # Format for JSON output
            output = {
                "proof": [f"0x{step.hex()}" for step in result.proof],
                "root": f"0x{result.root.hex()}",
                "metadata": {
                    **result.metadata,
                    "type": "balance_proof"
                }
            }
        
        print(format_proof_result(output))
        
    except Exception as e:
        logger.error(f"Error generating balance proof: {e}")
        raise click.ClickException(str(e))


@cli.command()
@click.argument('validator_index', type=int)
@click.option('--json-file', type=str, help='Path to JSON state file')
@click.option('--slot', type=int, help='Slot number for API queries (defaults to head)')
def proposer(validator_index: int, json_file: str = None, slot: int = None):
    """
    Generate a block proposer proof.
    
    VALIDATOR_INDEX: Index of the validator to prove as proposer
    """
    try:
        if json_file:
            # Load from local JSON file
            state = load_and_process_state(json_file)
            result = generate_proposer_proof(state, validator_index)
            
            # Format for JSON output
            output = {
                "proof": [f"0x{step.hex()}" for step in result.proof],
                "root": f"0x{result.root.hex()}",
                "metadata": {
                    **result.metadata,
                    "type": "proposer_proof"
                }
            }
        else:
            # Use API
            beacon_client = BeaconAPIClient()
            slot_id = slot if slot is not None else "head"
            
            # Get state data
            state_response = beacon_client.get_state(slot_id)
            
            # Save to temp file and load
            with open("temp_state.json", "w") as f:
                json.dump(state_response["data"], f)
            
            state = load_and_process_state("temp_state.json")
            
            # Get previous cycle data
            try:
                prev_slot = max(0, state.slot - 64)
                prev_state = beacon_client.get_state(prev_slot)
                prev_block = beacon_client.get_block(prev_slot)
                prev_state_root = bytes.fromhex(prev_state["data"]["root"][2:])
                prev_block_root = bytes.fromhex(prev_block["data"]["root"][2:])
            except:
                prev_state_root = None
                prev_block_root = None
            
            result = generate_proposer_proof(state, validator_index, prev_state_root, prev_block_root)
            
            # Format for JSON output
            output = {
                "proof": [f"0x{step.hex()}" for step in result.proof],
                "root": f"0x{result.root.hex()}",
                "metadata": {
                    **result.metadata,
                    "type": "proposer_proof"
                }
            }
        
        print(format_proof_result(output))
        
    except Exception as e:
        logger.error(f"Error generating proposer proof: {e}")
        raise click.ClickException(str(e))


@cli.command()
@click.option('--host', default='127.0.0.1', help='Host to bind to')
@click.option('--port', default=8000, type=int, help='Port to bind to')
@click.option('--dev', is_flag=True, help='Enable development mode with auto-reload')
@click.pass_context
def serve(ctx, host: str, port: int, dev: bool):
    """Start the REST API server."""
    try:
        console.print(Panel(
            f"Starting Bera Proofs API Server\n\n"
            f"🚀 Server: http://{host}:{port}\n"
            f"📖 Docs: http://{host}:{port}/docs\n"
            f"❤️ Health: http://{host}:{port}/health\n\n"
            f"Press Ctrl+C to stop",
            title="API Server",
            border_style="green"
        ))
        
        run_server(host=host, port=port, dev=dev)
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Server stopped by user[/yellow]")
    except Exception as e:
        console.print(f"[red]Server error: {e}[/red]", style="bold")
        if ctx.obj.get('verbose'):
            console.print_exception()
        sys.exit(1)


@cli.command()
@click.option('--json-file', '-f', help='JSON file path for visualization')
@click.option('--validator-index', '-i', type=int, help='Validator index for proof')
@click.pass_context
def visualize(ctx, json_file: Optional[str], validator_index: Optional[int]):
    """Visualize Merkle tree structure and proofs."""
    try:
        if json_file and validator_index is not None:
            console.print("[cyan]Generating proof visualization...[/cyan]")
            # This would integrate with the visualization module
            demo_visualization()
        else:
            console.print("[cyan]Showing Merkle tree structure...[/cyan]")
            from src.visualize_merkle import create_simple_tree_diagram
            create_simple_tree_diagram()
            
    except Exception as e:
        console.print(f"[red]Visualization error: {e}[/red]", style="bold")
        if ctx.obj.get('verbose'):
            console.print_exception()
        sys.exit(1)


@cli.command()
@click.pass_context
def interactive(ctx):
    """Interactive mode for proof generation."""
    console.print(Panel(
        "🔍 Welcome to Bera Proofs Interactive Mode\n\n"
        "This mode will guide you through generating Merkle proofs\n"
        "for validators, balances, and proposers.",
        title="Interactive Mode",
        border_style="blue"
    ))
    
    try:
        # Get proof type
        proof_types = ["validator", "balance", "proposer", "quit"]
        while True:
            console.print("\n[bold cyan]Available proof types:[/bold cyan]")
            for i, ptype in enumerate(proof_types, 1):
                console.print(f"  {i}. {ptype}")
            
            choice = IntPrompt.ask(
                "Select proof type",
                choices=[str(i) for i in range(1, len(proof_types) + 1)],
                default="1"
            )
            
            selected_type = proof_types[choice - 1]
            if selected_type == "quit":
                console.print("[yellow]Goodbye![/yellow]")
                break
            
            # Get parameters
            validator_index = IntPrompt.ask("Validator index")
            slot = Prompt.ask("Slot (head/finalized/number)", default="head")
            
            use_json = Confirm.ask("Use JSON file instead of API?", default=False)
            json_file = None
            if use_json:
                json_file = Prompt.ask("JSON file path")
            
            # Generate proof
            console.print(f"\n[cyan]Generating {selected_type} proof...[/cyan]")
            
            service = ProofService()
            if selected_type == "validator":
                result = service.get_validator_proof(validator_index, slot, json_file or "")
            elif selected_type == "balance":
                result = service.get_balances_proof(validator_index, slot, json_file or "")
            elif selected_type == "proposer":
                result = service.get_proposer_proof(validator_index, slot, json_file or "")
            
            print_proof_result(result, selected_type, "table")
            
            if not Confirm.ask("\nGenerate another proof?", default=True):
                break
                
    except KeyboardInterrupt:
        console.print("\n[yellow]Interactive mode cancelled[/yellow]")
    except Exception as e:
        console.print(f"[red]Interactive mode error: {e}[/red]", style="bold")
        if ctx.obj.get('verbose'):
            console.print_exception()
        sys.exit(1)


@cli.command()
@click.pass_context
def health(ctx):
    """Check the health of API endpoints and services."""
    console.print("[cyan]Checking system health...[/cyan]")
    
    try:
        # Check beacon API
        client = BeaconAPIClient()
        api_status = client.health_check()
        
        table = Table(title="System Health Check")
        table.add_column("Component", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Details")
        
        table.add_row(
            "Beacon API",
            "✅ Healthy" if api_status else "❌ Unhealthy",
            client.base_url
        )
        
        # Check proof service
        try:
            service = ProofService()
            table.add_row("Proof Service", "✅ Ready", "Initialized successfully")
        except Exception as e:
            table.add_row("Proof Service", "❌ Error", str(e))
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]Health check failed: {e}[/red]", style="bold")
        sys.exit(1)


@cli.command()
@click.argument('json_file', type=click.Path(exists=True))
@click.pass_context
def inspect(ctx, json_file: str):
    """Inspect beacon state JSON file."""
    try:
        console.print(f"[cyan]Inspecting {json_file}...[/cyan]")
        
        state = load_and_process_state(json_file)
        
        table = Table(title="Beacon State Information")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Slot", str(state.slot))
        table.add_row("Validators", str(len(state.validators)))
        table.add_row("Balances", str(len(state.balances)))
        table.add_row("Genesis Root", state.genesis_validators_root.hex()[:20] + "...")
        table.add_row("State Root", state.merkle_root().hex()[:20] + "...")
        
        console.print(table)
        
        # Show first few validators
        if len(state.validators) > 0:
            console.print("\n[bold cyan]First 5 Validators:[/bold cyan]")
            val_table = Table()
            val_table.add_column("Index", style="cyan")
            val_table.add_column("Pubkey", style="green")
            val_table.add_column("Balance", style="yellow")
            
            for i in range(min(5, len(state.validators))):
                pubkey = state.validators[i].pubkey.hex()
                balance = str(state.balances[i]) if i < len(state.balances) else "N/A"
                val_table.add_row(
                    str(i), 
                    f"{pubkey[:20]}...{pubkey[-20:]}", 
                    balance
                )
            
            console.print(val_table)
        
    except Exception as e:
        console.print(f"[red]Inspection failed: {e}[/red]", style="bold")
        if ctx.obj.get('verbose'):
            console.print_exception()
        sys.exit(1)


if __name__ == '__main__':
    cli() 