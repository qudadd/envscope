"""Compile the one-shot SystemConfiguration helper, without OS changes."""
from .build_timezone_worker import build

if __name__=='__main__':
    print(build(component='network'))
