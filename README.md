# GDB PTE Finder

GDB PTE Finder is a plugin made to facilitate system debugging with GDB and qemu. 

When GDB is attached to an entire system on qemu, it may be useful to convert virtual memory to physical memory, as well as access the page table entry and its flags. 

## Usage

Here's how to use your GDB plugin:

1. Start GDB in the terminal.
2. Load the plugin using the following command: `(gdb) source /path/to/PTEFinder.py`.
3. Use the plugin commands, for example: `(gdb) pte <virtual_address> [<CR3>]`.
4. Enjoy the output produced by the plugin!

```
(gdb) pte 0x00005595b2f5b57a
PML4 addr:	0xb152000	PML4 entry:	0x1b158067 [P RW S A]
PDPT addr:	0x1b158000	PDPT entry:	0x80a6067 [P RW S A]
PD addr:	0x80a6000	PD entry:	0x80a8067 [P RW S A D]
PT addr:	0x80a8000	PT entry:	0x1e930025 [P S A]
Physical addr:	0x1e93057a
```

## Installation

Here's how to install your GDB plugin:

1. Clone or download the repository to your local machine.
2. Move the plugin file to a directory in your `$PATH`.
3. Make the plugin file executable using the following command: `$ chmod +x /path/to/PTEFinder.py`.
4. Add the following line to your `~/.gdbinit` file: `source /path/to/PTEFinder`.
5. Start GDB and use the plugin as described in the Usage section.

## Contributing

If you want to contribute to this project, feel free to create a pull request or open an issue on the repository. Your contribution is always welcome!

I must state, though, that this was a one-time deal plugin I created for specific purposes. I have little to no intention of creating more features (unless I need them). 

## License

This project is licensed under MIT. Feel free to use, modify or roll it and smoke it as you see fit. I won't mind.

## Acknowledgements

Thanks to pythoneiro for the theoretical basis and sample codes provided.
