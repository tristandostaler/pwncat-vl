#!/usr/bin/env python3
import textwrap

import pwncat
import pwncat.modules
from pwncat.util import console
from pwncat.commands import Complete, Parameter, CommandDefinition, get_module_choices
from pwncat.workspace import WorkspaceError


class Command(CommandDefinition):
    """
    Run a module. If no module is specified, use the module in the
    current context. You can enter a module context with `module use`
    command.

    Module arguments can be appended to the run command with `variable=value`
    syntax. Arguments are type-checked prior to executing, and the results
    are displayed to the terminal.

    To locate available modules, you can use `module search`. To
    find documentation on individual modules including expected
    arguments, use `module info`. In a workspace console, use
    `module run --background NAME` for a module that opts in to safe
    background execution. Check `module status` and `module result` afterward.
    """

    PROG = "run"
    ARGS = {
        "--raw,-r": Parameter(
            Complete.NONE, action="store_true", help="Display raw results unformatted",
        ),
        "--traceback,-t": Parameter(
            Complete.NONE, action="store_true", help="Show traceback for module errors",
        ),
        "--background,-b": Parameter(
            Complete.NONE, action="store_true",
            help="Run an opted-in module in the background from a workspace console",
        ),
        "module": Parameter(
            Complete.CHOICES,
            nargs="?",
            metavar="MODULE",
            choices=get_module_choices,
            help="The module name to execute",
        ),
        "args": Parameter(Complete.NONE, nargs="*", help="Module arguments"),
    }

    def run(self, manager: "pwncat.manager.Manager", args):

        owner = getattr(manager, "workspace_console", None)
        if owner is not None and owner.modules.active() and not args.background:
            console.log(
                "[red]error[/red]: a background module is running; "
                "use 'module status' before starting another module"
            )
            return

        module_name = args.module

        if args.module is None and manager.config.module is None:
            console.log("[red]error[/red]: no module specified")
            return
        if args.module is None:
            module_name = manager.config.module.name

        # Parse key=value pairs
        values = {}
        for arg in args.args:
            if "=" not in arg:
                values[arg] = True
            else:
                name, value = arg.split("=")
                values[name] = value

        # pwncat.config.locals.update(values)
        config_values = manager.config.locals.copy()
        config_values.update(values)

        if args.background:
            if owner is None:
                console.log("[red]error[/red]: background modules require a workspace console")
                return
            try:
                owner.start_module(
                    module_name, config_values, raw=args.raw,
                    traceback_requested=args.traceback,
                )
                if args.module is not None:
                    manager.config.back()
            except (WorkspaceError, pwncat.modules.ModuleFailed) as exc:
                console.log(f"[red]error[/red]: {exc}")
            return

        try:
            result = manager.target.run(module_name, **config_values)

            if args.module is not None:
                manager.config.back()
        except pwncat.modules.ModuleNotFound:
            console.log(f"[red]error[/red]: {module_name}: not found")
            return
        except pwncat.modules.ArgumentFormatError as exc:
            console.log(f"[red]error[/red]: {exc}: invalid argument")
            return
        except pwncat.modules.MissingArgument as exc:
            console.log(f"[red]error[/red]: missing argument: {exc}")
            return
        except pwncat.modules.InvalidArgument as exc:
            console.log(f"[red]error[/red]: invalid argument: {exc}")
            return
        except pwncat.modules.ModuleFailed as exc:
            if args.traceback:
                console.print_exception()
            else:
                console.log(f"[red]error[/red]: module failed: {exc}")
            return

        self.display_result(manager, module_name, result, raw=args.raw)

    def display_result(self, manager, module_name, result, *, raw=False, session=None):
        """Render a foreground or completed background module result."""
        if isinstance(result, list):
            result = [r for r in result if not getattr(r, "hidden", False)]
        elif result is not None and getattr(result, "hidden", False):
            result = None

        if raw:
            console.print(result)
        else:

            if result is None or (isinstance(result, list) and not result):
                console.log(f"Module [bold]{module_name}[/bold] completed successfully")
                return

            if not isinstance(result, list):
                result = [result]
            self.display_item(manager, title=module_name, results=result, session=session)

    def display_item(self, manager, title, results, session=None):
        """Display a possibly complex item"""

        session = manager.target if session is None else session

        console.print(f"[bold underline]Module '{title}' Results[/bold underline]")

        # Uncategorized or raw results
        categories = {}
        uncategorized = []
        longform = []

        # Organize results by category
        for result in results:
            if isinstance(result, pwncat.modules.Result) and result.is_long_form(
                session,
            ):
                longform.append(result)
            elif (
                not isinstance(result, pwncat.modules.Result)
                or result.category(session) is None
            ):
                uncategorized.append(result)
            elif result.category(session) not in categories:
                categories[result.category(session)] = [result]
            else:
                categories[result.category(session)].append(result)

        # Show uncategorized results first
        if uncategorized:
            console.print("[bold]Uncategorized Results[/bold]")
            for result in uncategorized:
                console.print(
                    "- " + (
                        result.title(session)
                        if isinstance(result, pwncat.modules.Result)
                        else str(result)
                    )
                )

        # Show all other categories
        if categories:
            for category, results in categories.items():
                console.print(f"[bold]{category}[/bold]")
                for result in results:
                    console.print(f"  - {result.title(session)}")

        # Show long-form results in their own sections
        if longform:
            for result in longform:
                if result.category(session) is None:
                    console.print(f"[bold]{result.title(session)}[/bold]")
                else:
                    console.print(
                        f"[bold]{result.category(session)} - {result.title(session)}[/bold]",
                    )
                console.print(textwrap.indent(result.description(session), "  "))
