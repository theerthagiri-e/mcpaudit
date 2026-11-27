"""Enable `python -m mcpaudit ...` (no PATH entry needed)."""
import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
