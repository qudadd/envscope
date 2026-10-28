"""Run the native shell with an isolated fixture and no public probes."""
import sys
from envscope._desktop_test import main

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else None)
