import sys

from rich import print
from rich.table import Table


TABLE_TITLE_DEFAULTS = dict(
    title_justify="center",
    title_style="bold italic cyan",
)


def get_argv(idx, default=None):
    """Return the `sys.argv` value for the given index, defaulting on `None` or a supplied custom value."""
    try:
        return sys.argv[int(idx)]
    except IndexError:
        return default

def err_exit(message, arg_override=1):
    print(message)
    sys.exit(arg_override)

def emit_table(
    item_li, item_name, *col_names,
    row_extractor=lambda x:(x,), warn_on_empty=True,
    **tinit_kwargs
):
    """
    High level convenience util which entirely manages construction and subsequent display of a table.
    """
    if len(item_li) == 0:
        if warn_on_empty:
            print(f"\n[bold red]>>>[white] No {item_name}s found\n")
        return

    t = init_table(*col_names, **tinit_kwargs, title=f"* {item_name.title()}s *")
    for item in item_li:
        t.add_row(*row_extractor(item))
    print(t)

def init_table(*col_names, style=None, col_prefix="", justify="center", **title_kwargs):
    """
    Initialize a `rich.table` `Table`, with defaults common for this project.

    If you want, you can pass any number of column names as positional arguments;
    corresponding columns will be added for you.

    The keyword arguments specifically listed in the signature get applied
    to the internal `add_column` calls. All other, additional keyword arguments
    will be passed to `Table.__init__` (overriding defaults in case of collisions).

    If no additional keyword arguments meant for the title get passed,
    a `Table` object without a title is created.
    """
    t = Table() if len(title_kwargs) == 0 else Table(**{**TABLE_TITLE_DEFAULTS, **title_kwargs})
    for name in col_names:
        t.add_column(col_prefix+name, style=style, justify=justify)
    return t

def no_blanks(str_li):
    return (x for x in str_li if len(x.strip()) > 0)

def user_confirm(question_text):
    return str(input(question_text)).lower() == "y"

def stylize_bool(b, invert_style=False):
    prefix = "[bold green]" if b ^ invert_style else "[bold red]"
    return prefix + repr(b)
