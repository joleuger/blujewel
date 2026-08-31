/*
 * SPDX-FileCopyrightText: 2026 Johannes Leupolz
 * SPDX-License-Identifier: MIT
 * See testdata/fixtures/LICENSE.
 *
 * cmd_args.c -- BluJewel NE-format parser test fixture (OS/2 1.3)
 *
 * 13 lines of K&R-style C: prints each command-line argument on its own
 * line. Built with Microsoft C/C++ 5.1 for OS/2 1.3 (protected mode).
 * See the CMD_ARGS provenance note in testdata/fixtures/README.md.
 */
main(argc, argv, envp)
	int argc;
	char **argv;
	char **envp;

	{
	register char **p;

	for (p = argv; argc > 0; argc--,p++) {
		printf("%s\n", *p);
		}
	exit(0);
	}
