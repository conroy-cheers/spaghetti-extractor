/* SPDX-License-Identifier: GPL-3.0-or-later
 * Source-assisted lifting of the pinned Hello main/parse_options/print_help.
 * Original GNU Hello: Copyright (C) 1992-2026 Free Software Foundation, Inc.
 * This application uses the already lifted allocation/conversion/free bodies.
 * See COPYING.hello. */
#include "services.h"
#include "windows-1252.h"
#include "config.h"
#include <getopt.h>
#include <stdio.h>
#include <string.h>

static void print_help(const char *name) {
    spx_target_fprintf(stdout,"Usage: %s [OPTION]...\n"
        "Print a friendly, customizable greeting.\n\n"
        "  -t, --traditional       use traditional greeting\n"
        "  -g, --greeting=TEXT     use TEXT as the greeting message\n\n"
        "      --help     display this help and exit\n"
        "      --version  output version information and exit\n\n"
        "Report bugs to: bug-hello@gnu.org\n"
        "GNU Hello home page: <https://www.gnu.org/software/hello/>\n"
        "General help using GNU software: <https://www.gnu.org/gethelp/>\n",name);
}

static void print_version(void) {
    spx_target_fprintf(stdout,"hello (GNU Hello) 2.12.3\n"
        "Copyright (C) 2026 Free Software Foundation, Inc.\n"
        "License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.\n"
        "This is free software: you are free to change and redistribute it.\n"
        "There is NO WARRANTY, to the extent permitted by law.\n\n"
        "Written by Karl Berry, Sami Kerola, Jim Meyering,\n"
        "and Reuben Thomas.\n");
}

int hello_application(int argc, char **argv) {
    unsigned char state[4]; hello_reset(state);
    hello_start(argc,argv);
    const unsigned char *greeting=(const unsigned char *)"Hello, world!";
    const struct option options[]={
        {"greeting",required_argument,0,'g'}, {"traditional",no_argument,0,'t'},
        {"help",no_argument,0,128}, {"version",no_argument,0,129}, {0,0,0,0}};
    int bad=0, option;
    while ((option=getopt_long(argc,argv,"g:t",options,0))!=-1) {
        switch (option) {
        case 128: print_help(argv[0]); return 0;
        case 129: print_version(); return 0;
        case 'g': greeting=(const unsigned char *)optarg; break;
        case 't': greeting=(const unsigned char *)"hello, world"; break;
        default: bad=1; break;
        }
    }
    if (bad || optind<argc) {
        if (argv[optind]) spx_target_fprintf(stderr,"%s: extra operand: %s\n",
            spx_target_basename(argv[0]),argv[optind]);
        spx_target_fprintf(stderr,"Try '%s --help' for more information.\n",argv[0]);
        hello_runtime.exit_code=1; return 1;
    }
    size_t count=strlen((const char *)greeting)+1;
    if (count>=UINT32_C(0x40000000)) hello_allocation_failed();
    uint16_t *wide=hello_allocate((uint32_t)count*2);
    if (hello_convert(wide,&greeting,(uint32_t)count,state)==UINT32_MAX) {
        spx_target_fprintf(stderr,"%s: conversion to a multibyte string failed\n",spx_target_basename(argv[0]));
        hello_runtime.exit_code=1; return 1;
    }
    spx_target_put16(stdout,wide);
    hello_release(wide);
    return 0;
}
