# ch569tool

An open sourced python command line flash tool for flashing WinChipHead CH56x series RISC-V USB micro controllerwith bootloader version(BTV) v2.70.
(You can check the version by using the official CH55x Tool.)

Usage
------------
* __-f \<filename\>__ Erase the whole chip, and flash the bin file to the CH55x.
* __-r__ Issue reset and run after the flashing.

```bash
python3 -m ch55xtool -f THE_BINARY_FILE.bin
```


