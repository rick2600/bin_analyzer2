#! /usr/bin/env python
# -*- coding: utf-8 -*-

from bin_analyzer.bin_analyzer import BinAnalyzer
import argparse


def parse_args():

    parser = argparse.ArgumentParser(description='bin_analyzer: static analysis of ELF binaries')

    parser.add_argument(dest='file', type=str, 
        help='standalone binary or directory of binaries')
    parser.add_argument('-l', '--list', action='store_true', 
        help='list plugins')
    parser.add_argument('-p', '--plugins', nargs='?', type=str,
        help='plugins to run (ex.: -p basic_info,checksec)')    
    parser.set_defaults(no_color=False)

    return parser.parse_args()


def main():
    args = parse_args()
    bin_analyzer = BinAnalyzer(args)
    bin_analyzer.scan()


if __name__ == "__main__":
    main()